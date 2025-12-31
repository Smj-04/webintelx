import { useState } from "react";
import {
  FaSearch,
  FaBug,
  FaShieldAlt,
  FaExclamationTriangle,
  FaFileDownload,
} from "react-icons/fa";
import Footer from "../components/Footer";

export default function QuickScan() {
  const [input, setInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a URL or Email");

    setIsScanning(true);
    setScanDone(false);
    setError("");
    setResults(null);

    try {
      const res = await fetch("http://localhost:5000/api/quickscan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: input }),
      });

      const data = await res.json();

      if (!data.success) {
        setError(data.error);
      } else {
        setResults(data.data);
      }
    } catch (err) {
      setError("Network error — backend unreachable.");
    }

    setIsScanning(false);
    setScanDone(true);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col">
      
      {/* Header */}
      <div className="text-center py-16 bg-gradient-to-r from-purple-600 to-indigo-600 shadow-lg">
        <h1 className="text-4xl font-extrabold mb-3">Quick Scan</h1>
        <p className="text-gray-200 text-lg max-w-2xl mx-auto">
          A fast overview scan to identify basic security risks and exposures.
        </p>
      </div>

      {/* Description */}
      <div className="max-w-4xl mx-auto mt-10 px-6">
        <h2 className="text-2xl font-bold mb-4 text-indigo-400">
          What Quick Scan Includes
        </h2>
        <p className="text-gray-300 mb-6">
          Quick Scan performs lightweight checks such as DNS lookup, ping tests,
          security headers, and common open ports to give you an instant security overview.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-gray-800 p-5 rounded-xl flex gap-4 shadow">
            <FaBug className="text-red-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Basic Vulnerability Detection</h4>
              <p className="text-gray-400 text-sm mt-1">
                Checks outdated headers, mixed content, weak SSL, and misconfigurations.
              </p>
            </div>
          </div>

          <div className="bg-gray-800 p-5 rounded-xl flex gap-4 shadow">
            <FaShieldAlt className="text-green-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Security Headers Check</h4>
              <p className="text-gray-400 text-sm mt-1">
                Analyzes CSP, X-Frame-Options, HSTS, and XSS Protection.
              </p>
            </div>
          </div>

          <div className="bg-gray-800 p-5 rounded-xl flex gap-4 shadow">
            <FaExclamationTriangle className="text-yellow-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Open Ports Snapshot</h4>
              <p className="text-gray-400 text-sm mt-1">
                Quickly checks common ports like 80, 443, 22, and database ports.
              </p>
            </div>
          </div>

          <div className="bg-gray-800 p-5 rounded-xl flex gap-4 shadow">
            <FaSearch className="text-blue-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Exposure Check</h4>
              <p className="text-gray-400 text-sm mt-1">
                Checks DNS, IP leaks, and general exposure indicators.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Input Section */}
      <div className="flex flex-col items-center mt-14 px-4">
        <div className="bg-gray-800 p-6 rounded-2xl shadow-xl w-full max-w-xl">
          <label className="text-lg font-semibold">Enter URL or Email</label>

          <input
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="example.com or user@example.com"
            className="w-full mt-3 px-4 py-3 rounded-md bg-gray-700 text-white border border-gray-600 focus:border-indigo-400"
          />

          <button
            onClick={handleScan}
            className="mt-5 flex items-center justify-center w-full bg-indigo-600 hover:bg-indigo-700 transition py-3 rounded-md font-semibold"
          >
            <FaSearch className="mr-2 text-lg" />
            Start Quick Scan
          </button>

          {error && <p className="text-red-400 mt-3">{error}</p>}
        </div>
      </div>

      {/* Loader */}
      {isScanning && (
        <div className="mt-12 text-center animate-pulse">
          <h2 className="text-2xl font-semibold text-indigo-400">
            Running Checks...
          </h2>
          <p className="text-gray-400 mt-2">
            Scanning DNS, ports, headers, SSL...
          </p>
          <div className="mt-6 flex justify-center">
            <div className="w-12 h-12 border-4 border-gray-600 border-t-indigo-500 rounded-full animate-spin"></div>
          </div>
        </div>
      )}

      {/* Results */}
      {scanDone && results && (
        <div className="mt-16 px-4 mb-20">
          <div className="bg-gray-800 p-6 rounded-2xl shadow-xl max-w-3xl mx-auto">
            <h2 className="text-3xl font-bold text-green-400 mb-3">
              Quick Scan Results
            </h2>

            {/* DNS */}
            <h3 className="text-xl font-bold text-blue-400 mb-2">DNS Lookup</h3>
            <pre className="bg-black p-4 rounded-lg text-green-400 text-sm whitespace-pre-wrap">
              {results.dns}
            </pre>

            {/* Ping */}
            <h3 className="text-xl font-bold text-blue-400 mt-6 mb-2">Ping Test</h3>
            <pre className="bg-black p-4 rounded-lg text-green-400 text-sm whitespace-pre-wrap">
              {results.ping}
            </pre>

            {/* Headers */}
            <h3 className="text-xl font-bold text-blue-400 mt-6 mb-2">
              Security Headers
            </h3>
            <pre className="bg-black p-4 rounded-lg text-green-400 text-sm whitespace-pre-wrap">
              {JSON.stringify(results.headers, null, 2)}
            </pre>

            {/* Ports */}
            <h3 className="text-xl font-bold text-blue-400 mt-6 mb-2">Open Ports</h3>
            <pre className="bg-black p-4 rounded-lg text-yellow-400 text-sm whitespace-pre-wrap">
              {results.openPorts.length > 0
                ? results.openPorts
                    .map(p => `${p.port} (${p.name})`)
                    .join(", ")
                : "No common ports detected"}
            </pre>

            {/* SSL */}
            <h3 className="text-xl font-bold text-blue-400 mt-6 mb-2">
              SSL Certificate
            </h3>
            <pre className="bg-black p-4 rounded-lg text-green-400 text-sm whitespace-pre-wrap">
              {JSON.stringify(results.ssl, null, 2)}
            </pre>

            {/* ✅ WHATWEB (ONLY ADDITION) */}
            <h3 className="text-xl font-bold text-blue-400 mt-6 mb-2">
              Technology Fingerprinting (WhatWeb)
            </h3>
            <pre className="bg-black p-4 rounded-lg text-purple-400 text-sm whitespace-pre-wrap">
              {results.whatweb
                ? typeof results.whatweb === "string"
                  ? results.whatweb
                  : JSON.stringify(results.whatweb, null, 2)
                : "No technology data detected"}
            </pre>
            {/* Endpoint Detection */}
            <h3 className="text-xl font-bold text-blue-400 mt-6 mb-2">
              Endpoint & SQLi Detection
            </h3>

            <pre className="bg-black p-4 rounded-lg text-yellow-400 text-sm whitespace-pre-wrap">
              {JSON.stringify(results.endpoints, null, 2)}
            </pre>

            <button className="mt-6 flex items-center mx-auto bg-green-600 hover:bg-green-700 transition py-3 px-6 rounded-md text-lg font-semibold shadow-lg">
              <FaFileDownload className="mr-2" />
              Download PDF Report
            </button>
          </div>
        </div>
      )}
    <Footer />  
    </div>
  );
}
