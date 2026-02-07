import { useState, useEffect } from "react";
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

  // Trigger full scan via backend API and store unified result
  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a domain or company name");
    setIsScanning(true);
    setScanDone(false);
    setScanResult(null);

    try {
      // POST to existing backend endpoint. Using relative path so dev proxy works.
      const resp = await axios.post("http://localhost:5000/api/fullscan", { url: input }, { timeout: 0 });
      // store unified result object returned by backend
      setScanResult(resp.data);
      setScanDone(true);
    } catch (err) {
      console.error("FullScan API error:", err);
      alert("FullScan failed. See console for details.");
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
    <div className="min-h-screen bg-gray-900 text-white flex flex-col">

      {/* Header */}
      <div className="text-center py-16 bg-gradient-to-r from-blue-600 to-indigo-700 shadow-lg">
        <h1 className="text-4xl font-extrabold mb-3">Full Scan</h1>
        <p className="text-gray-200 text-lg max-w-2xl mx-auto">
          Deep OSINT + Reconnaissance + Vulnerability Assessment for complete intelligence.
        </p>
      </div>

      {/* What Full Scan Does */}
      <div className="max-w-5xl mx-auto mt-10 px-6">
        <h2 className="text-2xl font-bold mb-4 text-blue-400">What Full Scan Includes</h2>
        <p className="text-gray-300 mb-6">
          Full Scan performs a complete investigation into the target’s public exposure, internal weaknesses, 
          and web infrastructure footprint. It is designed for security professionals who want comprehensive results.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">

          {/* OSINT */}
          <div className="bg-gray-800 p-5 rounded-xl flex items-start gap-4 shadow">
            <FaUserSecret className="text-purple-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Deep OSINT Enumeration</h4>
              <p className="text-gray-400 text-sm mt-1">
                Scrapes public records, social sources, leak databases, DNS history, WHOIS, emails & metadata.
              </p>
            </div>
          </div>

          {/* Recon */}
          <div className="bg-gray-800 p-5 rounded-xl flex items-start gap-4 shadow">
            <FaNetworkWired className="text-green-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Infrastructure Reconnaissance</h4>
              <p className="text-gray-400 text-sm mt-1">
                Maps subdomains, servers, CDN layers, firewalls, hosting providers & entry points.
              </p>
            </div>
          </div>

          {/* Vuln assessment */}
          <div className="bg-gray-800 p-5 rounded-xl flex items-start gap-4 shadow">
            <FaBug className="text-red-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Vulnerability Assessment</h4>
              <p className="text-gray-400 text-sm mt-1">
                Detects SQLi, XSS, CSRF, Clickjacking, Open Redirects & exposed sensitive files.
              </p>
            </div>
          </div>

          {/* Fingerprinting */}
          <div className="bg-gray-800 p-5 rounded-xl flex items-start gap-4 shadow">
            <FaFingerprint className="text-yellow-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Technology Fingerprinting</h4>
              <p className="text-gray-400 text-sm mt-1">
                Identifies CMS, frameworks, JS libraries, outdated components & vulnerable versions.
              </p>
            </div>
          </div>

          {/* Ports & services */}
          <div className="bg-gray-800 p-5 rounded-xl flex items-start gap-4 shadow">
            <FaListUl className="text-pink-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Port & Service Mapping</h4>
              <p className="text-gray-400 text-sm mt-1">
                Performs deep port scans to fingerprint running services & detect outdated servers.
              </p>
            </div>
          </div>

          {/* Malware / phishing */}
          <div className="bg-gray-800 p-5 rounded-xl flex items-start gap-4 shadow">
            <FaSearch className="text-blue-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Malware & Phishing Indicators</h4>
              <p className="text-gray-400 text-sm mt-1">
                Scans domain reputation, blocklists, suspicious redirects & malware hosting markers.
              </p>
            </div>
          </div>

        </div>
      </div>

      {/* Input */}
      <div className="flex flex-col items-center mt-14 px-4">
        <div className="bg-gray-800 p-6 rounded-2xl shadow-xl w-full max-w-xl">
          <label className="text-lg font-semibold">Enter Domain or Company Name</label>

          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="example.com or company"
            className="w-full mt-3 px-4 py-3 rounded-md bg-gray-700 text-white outline-none placeholder-gray-400 border border-gray-600 focus:border-blue-400"
          />

          <button
            onClick={handleScan}
            className="mt-5 flex items-center justify-center w-full bg-blue-600 hover:bg-blue-700 transition py-3 rounded-md font-semibold text-white shadow-lg"
          >
            <FaSearch className="mr-2 text-lg" />
            Start Full Scan
          </button>
        </div>
      </div>

      {/* Loading */}
      {isScanning && (
        <div className="mt-12 text-center animate-pulse">
          <h2 className="text-2xl font-semibold text-blue-400">Running Deep Scan...</h2>
          <p className="text-gray-400 mt-2">This may take several minutes</p>

          <div className="mt-6 flex justify-center">
            <div className="w-12 h-12 border-4 border-gray-600 border-t-blue-500 rounded-full animate-spin"></div>
          </div>
        </div>
      )}

      {/* Results: replaced static placeholder with actual unified API rendering
          - Uses `scanResult` returned from `/api/fullscan`
          - Renders header (target + duration), risk summary, quickscan summary,
            and per-module vulnerability blocks with expandable details.
          - Keeps existing layout, colors and spacing but removes SQLMap-only assumptions.
      */}
      {scanDone && !isScanning && (
        <div className="mt-16 px-4">
          <div className="bg-gray-800 p-6 rounded-2xl shadow-xl max-w-4xl mx-auto">
            <h2 className="text-3xl font-bold text-green-400 mb-3">Full Scan Completed</h2>

            <p className="text-gray-300 mb-2">These results provide a complete breakdown of vulnerabilities and exposed assets.</p>

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
                        {v.domXss?.found ? (
                          <div className="space-y-2">
                            <div>
                              <strong>Parameter:</strong>{" "}
                              <span className="text-yellow-300">
                                {v.domXss.details?.parameter || "N/A"}
                              </span>
                            </div>

                            <div>
                              <strong>Payload:</strong>{" "}
                              <span className="text-green-300">
                                {v.domXss.details?.payload || "N/A"}
                              </span>
                            </div>

                            <div>
                              <strong>Evidence:</strong>{" "}
                              <span className="text-gray-300">
                                {v.domXss.details?.evidence || "N/A"}
                              </span>
                            </div>

                            <div>
                              <strong>Confidence:</strong>{" "}
                              <span className="text-blue-300">
                                {v.domXss.details?.confidence || "Unknown"}
                              </span>
                            </div>
                          </div>
                        ) : (
                          <div>No vulnerability detected</div>
                        )}
                      </ModuleBlock>


                      {/* Stored XSS */}
                      <ModuleBlock keyName="stored" title="Stored XSS" found={!!v.storedXss?.found}>
                        {v.storedXss?.found ? (
                          <div className="space-y-2">
                            <div>
                              <strong>Parameter:</strong>{" "}
                              <span className="text-yellow-300">
                                {v.storedXss.details?.parameter || "N/A"}
                              </span>
                            </div>

                            <div>
                              <strong>Payload:</strong>{" "}
                              <span className="text-green-300">
                                {v.storedXss.details?.payload || "N/A"}
                              </span>
                            </div>

                            <div>
                              <strong>Evidence:</strong>{" "}
                              <span className="text-gray-300">
                                {v.storedXss.details?.evidence || "N/A"}
                              </span>
                            </div>

                            <div>
                              <strong>Confidence:</strong>{" "}
                              <span className="text-blue-300">
                                {v.storedXss.details?.confidence || "Unknown"}
                              </span>
                            </div>
                          </div>
                        ) : (
                          <div>No vulnerability detected</div>
                        )}
                      </ModuleBlock>


                    {/* CSRF */}
                    <ModuleBlock keyName="csrf" title="CSRF" found={!!v.csrf?.found}>
                      {v.csrf?.found ? (
                        <>
                          <div className="mb-2">Vulnerable endpoints: <span className="text-yellow-300">{v.csrf.details?.vulnerableEndpoints?.length || 'N/A'}</span></div>
                          <ul className="list-disc pl-5">
                            {(v.csrf.details?.vulnerableEndpoints || []).map((ep, i) => (
                              <li key={i}>{ep.endpoint || ep}</li>
                            ))}
                          </ul>
                        </>
                      ) : (
                        <div>No vulnerability detected</div>
                      )}
                    </ModuleBlock>

                    {/* Clickjacking */}
                    <ModuleBlock keyName="click" title="Clickjacking" found={!!v.clickjacking?.vulnerable}>
                      {v.clickjacking?.vulnerable ? (
                        <>
                          <div className="mb-2">Issue: <span className="text-yellow-300">{v.clickjacking.details?.issue || 'Missing frame protections'}</span></div>
                          <div className="mb-2">Relevant headers:</div>
                          <ul className="list-disc pl-5">
                            {Object.entries(v.clickjacking.headers || {}).slice(0,6).map(([k, val]) => (
                              <li key={k}><span className="font-medium">{k}</span>: {String(val)}</li>
                            ))}
                          </ul>
                        </>
                      ) : (
                        <div>No vulnerability detected</div>
                      )}
                    </ModuleBlock>

                    {/* Command Injection */}
                    <ModuleBlock keyName="cmd" title="Command Injection" found={!!v.commandInjection?.found}>
                      {v.commandInjection?.found ? (
                        <>
                          <div className="mb-2">Evidence: <span className="text-yellow-300">{v.commandInjection.details?.evidence || v.commandInjection.details?.notes || 'Command execution indicators observed'}</span></div>
                          {v.commandInjection.details?.endpoints && (
                            <ul className="list-disc pl-5">
                              {v.commandInjection.details.endpoints.map((e, i) => <li key={i}>{e}</li>)}
                            </ul>
                          )}
                        </>
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
