import { useState } from "react";
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

  const handleScan = () => {
    if (!input.trim()) return alert("Please enter a domain or company name");
    setIsScanning(true);

    // simulate scan (backend later)
    setTimeout(() => {
      setIsScanning(false);
      setScanDone(true);
    }, 3500);
  };

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

      {/* Results */}
      {scanDone && !isScanning && (
        <div className="mt-16 px-4">
          <div className="bg-gray-800 p-6 rounded-2xl shadow-xl max-w-4xl mx-auto">
            <h2 className="text-3xl font-bold text-green-400 mb-3">Full Scan Completed</h2>

            <p className="text-gray-300 mb-6">
              These results provide a complete breakdown of vulnerabilities and exposed assets.
            </p>

            <div className="bg-gray-700 p-5 rounded-lg text-gray-300">

              <p className="mb-2">• Subdomains discovered: <span className="text-blue-400">12</span></p>
              <p className="mb-2">• Open ports identified: <span className="text-yellow-400">3</span></p>
              <p className="mb-2">• Critical vulnerabilities: <span className="text-red-400">2 Found</span></p>
              <p className="mb-2">• Data breaches: <span className="text-red-400">Email leaked in 1 breach</span></p>
              <p className="mb-2">• Technology stack: <span className="text-green-400">Angular, nginx, MySQL</span></p>

            </div>

            <button className="mt-6 flex items-center mx-auto bg-green-600 hover:bg-green-700 transition py-3 px-6 rounded-md text-lg font-semibold shadow-lg">
              <FaFileDownload className="mr-2" /> Download Full PDF Report
            </button>
          </div>
        </div>
      )}

      <div className="h-20"></div>
    </div>
  );
}
