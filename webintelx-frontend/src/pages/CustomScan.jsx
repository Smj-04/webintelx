import { useState } from "react";
import {
  FaBug,
  FaShieldAlt,
  FaNetworkWired,
  FaUserSecret,
  FaListUl,
  FaSearch,
  FaFileCode,
  FaFileDownload,
} from "react-icons/fa";

export default function CustomScan() {
  const [url, setUrl] = useState("");
  const [customScript, setCustomScript] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);

  const [selectedModules, setSelectedModules] = useState({
    subdomains: false,
    ports: false,
    vulnerabilities: false,
    osint: false,
    headers: false,
    sensitiveFiles: false,
  });

  const toggleModule = (module) => {
    setSelectedModules({
      ...selectedModules,
      [module]: !selectedModules[module],
    });
  };

  const handleScan = () => {
    if (!url.trim()) return alert("Please enter a target URL/domain");

    const selected = Object.values(selectedModules).some((v) => v === true);
    if (!selected && !customScript.trim()) {
      return alert("Please select at least one module or add a custom script.");
    }

    setIsScanning(true);

    setTimeout(() => {
      setIsScanning(false);
      setScanDone(true);
    }, 3500);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col">

      {/* Header */}
      <div className="text-center py-16 bg-gradient-to-r from-indigo-600 to-blue-600 shadow-lg">
        <h1 className="text-4xl font-extrabold mb-3">Custom Scan</h1>
        <p className="text-gray-200 text-lg max-w-2xl mx-auto">
          Select the exact modules you want to run — or even upload your own scanning scripts.
        </p>
      </div>

      {/* Module Selection */}
      <div className="max-w-5xl mx-auto mt-12 px-6">

        <h2 className="text-2xl font-bold text-indigo-400 mb-4">Choose Scan Modules</h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">

          {/* Subdomain Enumeration */}
          <label
            className="bg-gray-800 p-5 rounded-xl shadow flex items-start gap-4 cursor-pointer"
            onClick={() => toggleModule("subdomains")}
          >
            <input
              type="checkbox"
              checked={selectedModules.subdomains}
              onChange={() => toggleModule("subdomains")}
              className="mt-1 mr-2"
            />
            <FaNetworkWired className="text-blue-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Subdomain Enumeration</h4>
              <p className="text-gray-400 text-sm mt-1">
                Find subdomains, hidden services, and shadow infrastructure.
              </p>
            </div>
          </label>

          {/* Ports & Services */}
          <label
            className="bg-gray-800 p-5 rounded-xl shadow flex items-start gap-4 cursor-pointer"
            onClick={() => toggleModule("ports")}
          >
            <input
              type="checkbox"
              checked={selectedModules.ports}
              onChange={() => toggleModule("ports")}
              className="mt-1 mr-2"
            />
            <FaListUl className="text-yellow-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Port & Service Scan</h4>
              <p className="text-gray-400 text-sm mt-1">
                Detect open ports, fingerprint services, and catch insecure protocols.
              </p>
            </div>
          </label>

          {/* Vulnerability Scan */}
          <label
            className="bg-gray-800 p-5 rounded-xl shadow flex items-start gap-4 cursor-pointer"
            onClick={() => toggleModule("vulnerabilities")}
          >
            <input
              type="checkbox"
              checked={selectedModules.vulnerabilities}
              onChange={() => toggleModule("vulnerabilities")}
              className="mt-1 mr-2"
            />
            <FaBug className="text-red-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Vulnerability Checks</h4>
              <p className="text-gray-400 text-sm mt-1">
                SQLi, XSS, CSRF, Clickjacking, Open Redirects & other web attacks.
              </p>
            </div>
          </label>

          {/* OSINT */}
          <label
            className="bg-gray-800 p-5 rounded-xl shadow flex items-start gap-4 cursor-pointer"
            onClick={() => toggleModule("osint")}
          >
            <input
              type="checkbox"
              checked={selectedModules.osint}
              onChange={() => toggleModule("osint")}
              className="mt-1 mr-2"
            />
            <FaUserSecret className="text-purple-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">OSINT Collection</h4>
              <p className="text-gray-400 text-sm mt-1">
                Email leaks, breach databases, DNS history, WHOIS, metadata & web exposure.
              </p>
            </div>
          </label>

          {/* Headers */}
          <label
            className="bg-gray-800 p-5 rounded-xl shadow flex items-start gap-4 cursor-pointer"
            onClick={() => toggleModule("headers")}
          >
            <input
              type="checkbox"
              checked={selectedModules.headers}
              onChange={() => toggleModule("headers")}
              className="mt-1 mr-2"
            />
            <FaShieldAlt className="text-green-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Security Headers Audit</h4>
              <p className="text-gray-400 text-sm mt-1">
                CSP, HSTS, X-Frame-Options, XSS Protection & other critical headers.
              </p>
            </div>
          </label>

          {/* Sensitive Files */}
          <label
            className="bg-gray-800 p-5 rounded-xl shadow flex items-start gap-4 cursor-pointer"
            onClick={() => toggleModule("sensitiveFiles")}
          >
            <input
              type="checkbox"
              checked={selectedModules.sensitiveFiles}
              onChange={() => toggleModule("sensitiveFiles")}
              className="mt-1 mr-2"
            />
            <FaSearch className="text-pink-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Sensitive File Detection</h4>
              <p className="text-gray-400 text-sm mt-1">
                Detect exposed .env, config files, backups, logs & forgotten endpoints.
              </p>
            </div>
          </label>

        </div>
      </div>

      {/* Custom Script Section */}
      <div className="max-w-5xl mx-auto mt-12 px-6 mb-10">
<h2 className="text-2xl font-bold text-indigo-400 mb-4 flex items-center gap-2">
  <FaFileCode /> Add Custom Scan Script (Optional)
</h2>

        <textarea
          value={customScript}
          onChange={(e) => setCustomScript(e.target.value)}
          rows={6}
          placeholder="Paste your custom Python/JS shell script here..."
          className="w-full p-4 bg-gray-800 border border-gray-700 rounded-xl text-white placeholder-gray-500 outline-none focus:border-indigo-400"
        ></textarea>

        <p className="text-gray-500 text-sm mt-2">
          Your script will run in a sandboxed environment (backend integration later).
        </p>
      </div>

      {/* Input + Start Button */}
      <div className="flex flex-col items-center mb-10 px-6">
        <div className="bg-gray-800 p-6 rounded-2xl shadow-xl w-full max-w-xl">
          <label className="text-lg font-semibold">Target URL / Domain</label>

          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="example.com"
            className="w-full mt-3 px-4 py-3 rounded-md bg-gray-700 text-white outline-none placeholder-gray-400 border border-gray-600 focus:border-indigo-400"
          />

          <button
            onClick={handleScan}
            className="mt-5 flex items-center justify-center w-full bg-indigo-600 hover:bg-indigo-700 transition py-3 rounded-md font-semibold text-white shadow-lg"
          >
            <FaSearch className="mr-2 text-lg" />
            Start Custom Scan
          </button>
        </div>
      </div>

      {/* Loader */}
      {isScanning && (
        <div className="text-center animate-pulse">
          <h2 className="text-2xl font-semibold text-indigo-400">Running Your Custom Configuration...</h2>
          <p className="text-gray-400 mt-2">Modules and scripts executing</p>

          <div className="mt-6 flex justify-center mb-10">
            <div className="w-12 h-12 border-4 border-gray-600 border-t-indigo-500 rounded-full animate-spin"></div>
          </div>
        </div>
      )}

      {/* Results */}
      {scanDone && !isScanning && (
        <div className="px-4 mb-10">
          <div className="bg-gray-800 p-6 rounded-2xl shadow-xl max-w-4xl mx-auto">
            <h2 className="text-3xl font-bold text-green-400 mb-3">Custom Scan Results</h2>

            <p className="text-gray-300 mb-6">
              Below are results based on your selected modules & custom script.
            </p>

            <div className="bg-gray-700 p-5 rounded-lg text-gray-300">
              <p className="mb-2">• Modules selected: <span className="text-blue-400">{Object.keys(selectedModules).filter((m) => selectedModules[m]).length}</span></p>
              <p className="mb-2">• Custom script included: {customScript ? <span className="text-green-400">Yes</span> : <span className="text-red-400">No</span>}</p>
              <p className="mb-2">• Sample alerts: <span className="text-yellow-400">5 findings</span></p>
            </div>

            <button className="mt-6 flex items-center mx-auto bg-green-600 hover:bg-green-700 transition py-3 px-6 rounded-md text-lg font-semibold shadow-lg">
              <FaFileDownload className="mr-2" /> Download PDF Report
            </button>
          </div>
        </div>
      )}

    </div>
  );
}
