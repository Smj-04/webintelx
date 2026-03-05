import { useState, useEffect, useRef } from "react";
import axios from "axios";
import {
  FaSearch,
  FaFingerprint,
  FaNetworkWired,
  FaBug,
  FaUserSecret,
  FaListUl,
  FaFileDownload,
} from "react-icons/fa";

export default function FullScan() {
  const [input, setInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [expanded, setExpanded] = useState({});
  const [error, setError] = useState(null);
  const [showRawDomFindings, setShowRawDomFindings] = useState(false);
  const loaderRef = useRef(null);

  // Trigger full scan via backend API and store unified result
  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a domain or company name");

    setIsScanning(true);
    setScanDone(false);
    setScanResult(null);
    setError(null);
    setTimeout(() => loaderRef.current?.scrollIntoView({ behavior: "smooth" }), 100);

    try {
      const resp = await axios.post(
        "http://localhost:5000/api/fullscan",
        { url: input },
        { timeout: 0 }
      );

      setScanResult(resp.data);
      setScanDone(true);

    } catch (err) {

      if (err.response) {
        // 🔹 This catches your backend 400 validation error
        setError(err.response.data.error || "Invalid target");
      } else {
        setError("Backend not reachable or network error.");
      }

    } finally {
      setIsScanning(false);
    }
  };

  const downloadPDF = async () => {
  const resp = await axios.post(
    "/api/fullscan/pdf",
    { scanData: scanResult, target: scanResult.target },
    { responseType: "blob" }
  );

  const blob = new Blob([resp.data], { type: "application/pdf" });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `FullScan-${scanResult.target}.pdf`;
  a.click();
};

  // Helper: toggle expandable panels per module
  const toggle = (key) => setExpanded((s) => ({ ...s, [key]: !s[key] }));

return (
  <div className="min-h-screen bg-[#0f172a] text-white relative overflow-hidden flex flex-col">

    {/* GRID BACKGROUND (same as Home) */}
    <div className="absolute inset-0 bg-[linear-gradient(rgba(56,189,248,0.05)_1px,transparent_1px),linear-gradient(90deg,rgba(56,189,248,0.05)_1px,transparent_1px)] bg-[size:40px_40px] opacity-30"></div>

    {/* Header */}
    <div className="relative z-10 text-center py-20">
      <h1 className="text-5xl font-extrabold mb-4 bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
        Full Scan
      </h1>
      <p className="text-slate-400 text-lg max-w-2xl mx-auto">
        Deep OSINT + Reconnaissance + Vulnerability Assessment for complete intelligence.
      </p>
    </div>

    {/* What Full Scan Does */}
    <div className="relative z-10 max-w-5xl mx-auto mt-10 px-6">
      <h2 className="text-2xl font-bold mb-4 text-sky-400">What Full Scan Includes</h2>
      <p className="text-slate-400 mb-6">
        Full Scan performs a complete investigation into the target’s public exposure, internal weaknesses,
        and web infrastructure footprint. It is designed for security professionals who want comprehensive results.
      </p>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">

        {/* OSINT */}
        <div className="bg-slate-800/60 backdrop-blur-md border border-slate-700 p-5 rounded-xl flex items-start gap-4 shadow">
          <FaUserSecret className="text-purple-400 text-3xl mt-1" />
          <div>
            <h4 className="text-lg font-semibold">Deep OSINT Enumeration</h4>
            <p className="text-slate-400 text-sm mt-1">
              Scrapes public records, social sources, leak databases, DNS history, WHOIS, emails & metadata.
            </p>
          </div>
        </div>

        {/* Recon */}
        <div className="bg-slate-800/60 backdrop-blur-md border border-slate-700 p-5 rounded-xl flex items-start gap-4 shadow">
          <FaNetworkWired className="text-green-400 text-3xl mt-1" />
          <div>
            <h4 className="text-lg font-semibold">Infrastructure Reconnaissance</h4>
            <p className="text-slate-400 text-sm mt-1">
              Maps subdomains, servers, CDN layers, firewalls, hosting providers & entry points.
            </p>
          </div>
        </div>

        {/* Vuln assessment */}
        <div className="bg-slate-800/60 backdrop-blur-md border border-slate-700 p-5 rounded-xl flex items-start gap-4 shadow">
          <FaBug className="text-red-400 text-3xl mt-1" />
          <div>
            <h4 className="text-lg font-semibold">Vulnerability Assessment</h4>
            <p className="text-slate-400 text-sm mt-1">
              Detects SQLi, XSS (DOM/Stored/Reflected), Clickjacking, Command Injection & exposed sensitive files.
            </p>
          </div>
        </div>

        {/* Fingerprinting */}
        <div className="bg-slate-800/60 backdrop-blur-md border border-slate-700 p-5 rounded-xl flex items-start gap-4 shadow">
          <FaFingerprint className="text-yellow-400 text-3xl mt-1" />
          <div>
            <h4 className="text-lg font-semibold">Technology Fingerprinting</h4>
            <p className="text-slate-400 text-sm mt-1">
              Identifies CMS, frameworks, JS libraries, outdated components & vulnerable versions.
            </p>
          </div>
        </div>

        {/* Ports */}
        <div className="bg-slate-800/60 backdrop-blur-md border border-slate-700 p-5 rounded-xl flex items-start gap-4 shadow">
          <FaListUl className="text-pink-400 text-3xl mt-1" />
          <div>
            <h4 className="text-lg font-semibold">Port & Service Mapping</h4>
            <p className="text-slate-400 text-sm mt-1">
              Performs deep port scans to fingerprint running services & detect outdated servers.
            </p>
          </div>
        </div>

        {/* Malware */}
        <div className="bg-slate-800/60 backdrop-blur-md border border-slate-700 p-5 rounded-xl flex items-start gap-4 shadow">
          <FaSearch className="text-sky-400 text-3xl mt-1" />
          <div>
            <h4 className="text-lg font-semibold">Malware & Phishing Indicators</h4>
            <p className="text-slate-400 text-sm mt-1">
              Scans domain reputation, blocklists, suspicious redirects & malware hosting markers.
            </p>
          </div>
        </div>

      </div>
    </div>

    {/* Input */}
    <div className="relative z-10 flex flex-col items-center mt-14 px-4">
      <div className="bg-slate-800/60 backdrop-blur-md border border-slate-700 p-6 rounded-2xl shadow-xl w-full max-w-xl">
        <label className="text-lg font-semibold">Enter Domain or URL</label>

        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="example.com or company"
          onKeyDown={(e) => e.key === "Enter" && handleScan()}
          className="w-full mt-3 px-4 py-3 rounded-lg bg-slate-900 text-white outline-none placeholder-slate-500 border border-slate-700 focus:border-sky-400"
        />

        <button
          onClick={handleScan}
          className="mt-5 flex items-center justify-center w-full bg-sky-500 hover:bg-sky-400 transition py-3 rounded-lg font-semibold text-black shadow-lg shadow-sky-500/20"
        >
          <FaSearch className="mr-2 text-lg" />
          Start Full Scan
        </button>
      </div>
    </div>

    {error && (
      <div className="relative z-10 mt-6 text-center">
        <div className="bg-red-600 text-white px-4 py-3 rounded-lg max-w-xl mx-auto">
          {error}
        </div>
      </div>
    )}

    {/* Loading */}
    {isScanning && (
      <div ref={loaderRef} className="relative z-10 mt-12 text-center animate-pulse">
        <h2 className="text-2xl font-semibold text-sky-400">Running Deep Scan...</h2>
        <p className="text-slate-400 mt-2">This may take several minutes</p>

        <div className="mt-6 flex justify-center">
          <div className="w-12 h-12 border-4 border-slate-700 border-t-sky-500 rounded-full animate-spin"></div>
        </div>
      </div>
    )}

    {/* RESULTS */}
    {scanDone && !isScanning && (
      <div className="relative z-10 mt-16 px-4">
        <div className="bg-slate-900 border border-slate-700 p-6 rounded-2xl shadow-xl max-w-4xl mx-auto">

          <h2 className="text-3xl font-bold text-green-400 mb-3">Full Scan Completed</h2>

          <p className="text-slate-400 mb-2">
            These results provide a complete breakdown of vulnerabilities and exposed assets.
          </p>

          {/* EVERYTHING BELOW REMAINS EXACT SAME LOGIC */}

            {/* Header details: target + duration */}
            <div className="bg-gray-700 p-4 rounded-lg text-gray-300 mb-4">
              <p className="mb-1">• Target: <span className="text-blue-400">{(scanResult && scanResult.target) || input}</span></p>
              <p className="mb-1">• Scan started: <span className="text-yellow-300">{scanResult?.meta?.startedAt ? new Date(scanResult.meta.startedAt).toLocaleString() : '—'}</span></p>
              <p className="mb-1">• Scan completed: <span className="text-yellow-300">{scanResult?.meta?.completedAt ? new Date(scanResult.meta.completedAt).toLocaleString() : '—'}</span></p>
              <p className="mb-1">• Duration: <span className="text-green-200">{(scanResult && scanResult.meta && scanResult.meta.startedAt && scanResult.meta.completedAt) ?
                `${Math.max(0, (new Date(scanResult.meta.completedAt) - new Date(scanResult.meta.startedAt))/1000).toFixed(0)}s` : '—'}</span></p>
            </div>

            {/* Risk Summary Section */}
            <div className="flex gap-3 mb-4 flex-wrap">
              <div className="bg-gray-700 p-3 rounded w-full sm:w-auto">
                <div className="text-sm text-gray-400">Critical</div>
                <div className="text-xl font-bold text-red-400">{scanResult?.summary?.critical ?? 0}</div>
              </div>
              <div className="bg-gray-700 p-3 rounded w-full sm:w-auto">
                <div className="text-sm text-gray-400">High</div>
                <div className="text-xl font-bold text-orange-400">{scanResult?.summary?.high ?? 0}</div>
              </div>
              <div className="bg-gray-700 p-3 rounded w-full sm:w-auto">
                <div className="text-sm text-gray-400">Medium</div>
                <div className="text-xl font-bold text-yellow-400">{scanResult?.summary?.medium ?? 0}</div>
              </div>
              <div className="bg-gray-700 p-3 rounded w-full sm:w-auto">
                <div className="text-sm text-gray-400">Low</div>
                <div className="text-xl font-bold text-green-400">{scanResult?.summary?.low ?? 0}</div>
              </div>
            </div>

            {/* QuickScan Summary Section (compact, read-only) */}
            <div className="bg-gray-700 p-4 rounded-lg text-gray-300 mb-6">
              <p className="mb-1">• Subdomains discovered: <span className="text-blue-400">{scanResult?.quickscan?.attackSurface?.subdomainCount ?? 0}</span></p>
              <p className="mb-1">• Parameterized endpoints: <span className="text-blue-400">{scanResult?.quickscan?.attackSurface?.endpointCount ?? 0}</span></p>
              <p className="mb-1">• Open ports: <span className="text-yellow-400">{scanResult?.quickscan?.attackSurface?.openPorts ?? 0}</span></p>
              <p className="mb-1">• Backend technology: <span className="text-green-400">{scanResult?.quickscan?.technology?.backend ?? 'Unknown'}</span></p>
              <p className="mb-1">• SSL: <span className="text-green-200">{scanResult?.quickscan?.technology?.ssl ? 'Yes' : 'No'}</span></p>
            </div>

            {/* Vulnerability Results Section: module-specific blocks */}
            <div className="space-y-4">
              {/* Render helper inline to keep structure compact and readable */}
              {(() => {
                const v = scanResult?.vulnerabilities || {};

                const ModuleBlock = ({ keyName, title, found, children }) => (
                  <div className="bg-gray-700 p-4 rounded-lg">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div className={`px-2 py-1 rounded text-sm ${found ? 'bg-red-600 text-white' : 'bg-green-600 text-white'}`}>
                          {found ? 'VULNERABLE' : 'NOT FOUND'}
                        </div>
                        <h4 className="text-lg font-semibold">{title}</h4>
                      </div>
                      <div>
                        <button onClick={() => toggle(keyName)} className="text-sm px-3 py-1 rounded bg-gray-800 hover:bg-gray-600">{expanded[keyName] ? 'Hide' : 'Details'}</button>
                      </div>
                    </div>
                    {expanded[keyName] && (
                      <div className="mt-3 text-gray-300">
                        {children}
                      </div>
                    )}
                  </div>
                );

                return (
                  <>
                    {/* SQL Injection */}
                    <ModuleBlock keyName="sql" title="SQL Injection" found={!!v.sqlInjection?.found}>
                      {v.sqlInjection?.details?.findings?.length > 0 ? (
                        <ul className="list-disc pl-5">
                          {v.sqlInjection.details.findings.map((f, i) => (
                            <li key={i} className="mb-2">
                              <div className="font-medium">Endpoint: <span className="text-blue-300">{f.url}</span></div>
                              <div>Parameter: <span className="text-yellow-300">{f.param}</span></div>
                              <div>Databases: <span className="text-green-300">{(f.databases || []).join(', ') || 'N/A'}</span></div>
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <div>No vulnerability details provided by module.</div>
                      )}
                      </ModuleBlock>
                      
                      {/* DOM XSS */}
                      <ModuleBlock keyName="dom" title="DOM XSS" found={!!v.domXss?.found}>
                        {v.domXss?.details ? (
                          (() => {
                            const findings = Array.isArray(v.domXss.details.evidence) ? v.domXss.details.evidence : [];
                            const highMedium = findings.filter(f => (f.confidence || '').toLowerCase() === 'high' || (f.confidence || '').toLowerCase() === 'medium');
                            const lowCount = findings.length - highMedium.length;

                            if (highMedium.length > 0) {
                              return (
                                <div className="space-y-3">
                                  <div>Confirmed findings: <span className="text-red-300 font-semibold">{highMedium.length}</span></div>
                                  <ul className="list-disc pl-5">
                                    {highMedium.map((f, i) => (
                                      <li key={i} className="mb-2">
                                        <div className="font-medium">{f.type || 'DOM XSS'}</div>
                                        <div className="text-sm text-blue-300">{f.location || 'Location unavailable'}</div>
                                        <div className="text-xs text-gray-300">Confidence: {f.confidence || 'Unknown'}</div>
                                      </li>
                                    ))}
                                  </ul>
                                  {lowCount > 0 && <div className="text-sm text-gray-400">{lowCount} low-confidence finding(s) suppressed from view.</div>}
                                  <button onClick={() => setShowRawDomFindings(s => !s)} className="text-sm text-sky-400 underline">{showRawDomFindings ? 'Hide raw findings' : 'Show raw findings'}</button>
                                  {showRawDomFindings && (
                                    <div className="mt-2 text-xs text-gray-300">
                                      <pre className="whitespace-pre-wrap max-h-48 overflow-auto">{JSON.stringify(findings, null, 2)}</pre>
                                    </div>
                                  )}
                                </div>
                              );
                            }

                            if (findings.length > 0) {
                              return (
                                <div className="text-sm text-gray-400">No confirmed High/Medium findings. {findings.length} low-confidence finding(s) detected and suppressed. <button onClick={() => setShowRawDomFindings(s => !s)} className="text-sm text-sky-400 underline">{showRawDomFindings ? 'Hide raw findings' : 'Show raw findings'}</button></div>
                              );
                            }

                            return <div>No vulnerability detected</div>;
                          })()
                        ) : (
                          <div>No vulnerability detected</div>
                        )}
                      </ModuleBlock>

                      {/* Stored XSS */}
                      <ModuleBlock keyName="stored" title="Stored XSS" found={!!v.storedXss?.found}>
                        {v.storedXss?.details?.evidence ? (
                          Array.isArray(v.storedXss.details.evidence) ? (
                            <ul className="list-disc pl-5 space-y-2">
                              {v.storedXss.details.evidence.map((finding, idx) => (
                                <li key={idx} className="mb-3">
                                  <div><strong>Finding {idx + 1}:</strong> <span className="text-red-300">Form Location</span></div>
                                  <div className="ml-4 mt-1">
                                    <div>Location: <span className="text-blue-300">{finding.location || 'N/A'}</span></div>
                                    <div>Payload: <span className="text-yellow-300">{finding.payload ? finding.payload.substring(0, 50) : 'N/A'}...</span></div>
                                    <div>Evidence: <span className="text-green-300">{finding.evidence || 'N/A'}</span></div>
                                    <div>Confidence: <span className="text-orange-300">{finding.confidence || 'Unknown'}</span></div>
                                  </div>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <div className="text-gray-400">{v.storedXss.details.notes || "Vulnerability detected but details unavailable"}</div>
                          )
                        ) : (
                          <div>No vulnerability detected</div>
                        )}
                      </ModuleBlock>


                    {/* Module removed */}

                    {/* Reflected XSS (AutoXSS) */}
                    <ModuleBlock keyName="reflected" title="Reflected XSS" found={!!v.reflectedXss?.found}>
                      {v.reflectedXss?.details ? (
                        <div className="space-y-3">
                          <div>
                            Endpoints tested: <span className="text-blue-300 font-semibold">{v.reflectedXss.details.testedEndpoints || 0}</span>
                          </div>
                          <div>
                            Vulnerable endpoints: <span className="text-red-300 font-semibold">{(v.reflectedXss.details.vulnerableEndpoints || []).length || 0}</span>
                          </div>
                          {v.reflectedXss.details.vulnerableEndpoints && v.reflectedXss.details.vulnerableEndpoints.length > 0 && (
                            <div>
                              <strong>Vulnerable URLs:</strong>
                              <ul className="list-disc pl-5 mt-2 space-y-2">
                                {v.reflectedXss.details.vulnerableEndpoints.slice(0, 10).map((ep, idx) => (
                                  <li key={idx} className="mb-2">
                                    <div className="font-medium text-yellow-300 text-sm">{ep.url || 'Unknown'}</div>
                                    {Array.isArray(ep.findings) && ep.findings.length > 0 && (
                                      <div className="ml-4 mt-1 text-sm">
                                        <span className="text-green-300">Payloads detected: {ep.findings.length}</span>
                                        <ul className="list-circle pl-4 mt-1">
                                          {ep.findings.slice(0, 3).map((f, fIdx) => (
                                            <li key={fIdx} className="text-gray-300 text-xs">{f.type || f || 'Finding'}</li>
                                          ))}
                                        </ul>
                                      </div>
                                    )}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div>No vulnerability detected</div>
                      )}
                    </ModuleBlock>

                    {/* Clickjacking */}
                    <ModuleBlock keyName="click" title="Clickjacking" found={!!v.clickjacking?.vulnerable}>
                      {v.clickjacking?.vulnerable ? (
                        <div className="space-y-3">
                          <div>
                            <strong>Issue:</strong> <span className="text-red-300">{v.clickjacking.details?.issue || 'Missing X-Frame-Options / CSP frame-ancestors'}</span>
                          </div>
                          {v.clickjacking.details?.headers && Object.keys(v.clickjacking.details.headers).length > 0 ? (
                            <div>
                              <strong>Relevant Security Headers:</strong>
                              <ul className="list-disc pl-5 mt-2">
                                {Object.entries(v.clickjacking.details.headers || {}).slice(0, 8).map(([k, val]) => (
                                  <li key={k} className="text-sm">
                                    <span className="font-medium text-yellow-300">{k}:</span> <span className="text-gray-300">{String(val).substring(0, 60)}...</span>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          ) : v.clickjacking.headers ? (
                            <div className="text-gray-400 text-sm">No security headers detected</div>
                          ) : null}
                        </div>
                      ) : (
                        <div>No vulnerability detected</div>
                      )}
                    </ModuleBlock>

                    {/* Command Injection */}
                    <ModuleBlock keyName="cmd" title="Command Injection" found={!!v.commandInjection?.found}>
                      {v.commandInjection?.found ? (
                        <div className="space-y-3">
                          <div>
                            <strong>Confidence Level:</strong> <span className="text-orange-300 font-semibold">{v.commandInjection.details?.confidence || 'Unknown'}</span>
                          </div>
                          <div>
                            <strong>Description:</strong> <span className="text-gray-300">{v.commandInjection.details?.notes || 'Command execution vulnerability confirmed'}</span>
                          </div>
                          {Array.isArray(v.commandInjection.details?.evidence) && v.commandInjection.details.evidence.length > 0 && (
                            <div>
                              <strong>Vulnerable Parameters:</strong>
                              <ul className="list-disc pl-5 mt-2 space-y-2">
                                {v.commandInjection.details.evidence.slice(0, 5).map((finding, idx) => (
                                  <li key={idx} className="mb-2">
                                    <div><strong>Finding {idx + 1}:</strong></div>
                                    <div className="ml-4 mt-1 text-sm">
                                      <div>Parameter: <span className="text-yellow-300">{finding.parameter || 'Unknown'}</span></div>
                                      <div>Payload: <span className="text-green-300">{finding.payload ? finding.payload.substring(0, 40) : 'N/A'}...</span></div>
                                      <div>Evidence: <span className="text-blue-300">{finding.evidence || 'N/A'}</span></div>
                                    </div>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div>No vulnerability detected</div>
                      )}
                    </ModuleBlock>
                    {/* CSRF */}
                    <ModuleBlock keyName="csrf" title="CSRF (Cross-Site Request Forgery)" found={!!v.csrf?.found}>
                      {v.csrf?.found ? (
                        <div className="space-y-3">
                          <div>
                            Total Endpoints Tested:{" "}
                            <span className="text-blue-300 font-semibold">
                              {v.csrf.details?.summary?.totalEndpoints || 0}
                            </span>
                          </div>
                          <div>
                            Vulnerable Endpoints:{" "}
                            <span className="text-red-300 font-semibold">
                              {v.csrf.details?.summary?.vulnerable || 0}
                            </span>
                          </div>
                          <div>
                            Safe Endpoints:{" "}
                            <span className="text-green-300 font-semibold">
                              {v.csrf.details?.summary?.safe || 0}
                            </span>
                          </div>
                          {v.csrf.details?.vulnerableEndpoints?.length > 0 && (
                            <div>
                              <strong>Vulnerable Endpoints:</strong>
                              <ul className="list-disc pl-5 mt-2 space-y-2">
                                {v.csrf.details.vulnerableEndpoints.slice(0, 10).map((ep, idx) => (
                                  <li key={idx} className="mb-2">
                                    <div className="font-medium text-yellow-300 text-sm">
                                      {ep.endpoint || "Unknown"}
                                    </div>
                                    <div className="ml-4 mt-1 text-sm space-y-1">
                                      <div>
                                        Method:{" "}
                                        <span className="text-blue-300">{ep.method || "POST"}</span>
                                      </div>
                                      <div>
                                        Confidence:{" "}
                                        <span className="text-orange-300">{ep.confidence || "Unknown"}</span>
                                      </div>
                                      <div>
                                        Risk:{" "}
                                        <span className={ep.risk === "HIGH" ? "text-red-400 font-semibold" : "text-yellow-300"}>
                                          {ep.risk || "MEDIUM"}
                                        </span>
                                      </div>
                                    </div>
                                  </li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      ) : (
                        <div>No vulnerability detected</div>
                      )}
                    </ModuleBlock>
                  </>
                );
              })()}
            </div>

            <button
              onClick={downloadPDF}
              className="mt-6 flex items-center mx-auto bg-green-600 hover:bg-green-700 transition py-3 px-6 rounded-md text-lg font-semibold shadow-lg"
            >
              <FaFileDownload className="mr-2" /> Download Full PDF Report
            </button>
          </div>
        </div>
      )}

      <div className="h-20"></div>
    </div>
  );
}
