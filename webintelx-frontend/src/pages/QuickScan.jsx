import { useState } from "react";
import {
  FaSearch,
  FaBug,
  FaShieldAlt,
  FaExclamationTriangle,
  FaFileDownload,
} from "react-icons/fa";
import Footer from "../components/Footer";

const formatAIReport = (report) => {
  return report.split("\n").map((line, index) => {
    const clean = line.replace(/[#*]/g, "").trim();
    if (!clean) return null;

    const upper = clean.toUpperCase();

    // 🔵 MAIN HEADINGS
    if (
      upper === "EXECUTIVE SUMMARY" ||
      upper === "FINDINGS" ||
      upper === "METHODOLOGY" ||
      upper === "COMPLIANCE MAPPING" ||
      upper === "RECOMMENDATIONS" ||
      upper === "REMEDIATION" ||
      upper.match(/^\d+\.\s*(EXECUTIVE SUMMARY|FINDINGS|METHODOLOGY|COMPLIANCE MAPPING|RECOMMENDATIONS|REMEDIATION)$/)
    ) {
      return (
        <h2
          key={index}
          className="text-2xl font-bold text-indigo-700 mt-8 mb-4 border-b border-indigo-300 pb-2"
        >
          {clean}
        </h2>
      );
    }


    // 🟢 SUB-HEADINGS
  if (clean.endsWith(":")) {
    return (
      <h4
        key={index}
        className="text-lg font-semibold text-teal-700 mt-6 mb-2"
      >
        {clean}
      </h4>
    );
  }


    // 🔴 HIGH / CRITICAL
    if (upper.includes("CRITICAL") || upper.includes("HIGH")) {
      return (
        <p
          key={index}
          className="mt-2 text-red-600 font-semibold"
        >
          ⚠ {clean}
        </p>
      );
    }

    // 🟡 MEDIUM
    if (upper.includes("MEDIUM")) {
      return (
        <p
          key={index}
          className="mt-2 text-yellow-600 font-semibold"
        >
          ⚠ {clean}
        </p>
      );
    }

    // 🟢 LOW
    if (upper.includes("LOW")) {
      return (
        <p
          key={index}
          className="mt-2 text-green-600 font-semibold"
        >
          ℹ {clean}
        </p>
      );
    }

    // ⚪ NORMAL PARAGRAPH TEXT
    return (
      <p
        key={index}
        className="mt-2 text-lg text-gray-900 leading-relaxed"
      >
        {clean}
      </p>
    );
  });
};


export default function QuickScan() {
  const [input, setInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");

  // ✅ AI STATES (must be inside component)
  const [aiReport, setAiReport] = useState("");
  const [isGeneratingReport, setIsGeneratingReport] = useState(false);

  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a URL");

    setIsScanning(true);
    setError("");
    setResults(null);
    setAiReport("");
    setScanDone(false);

    try {
      // 🔹 STEP 1: Run QuickScan
      const scanRes = await fetch("http://localhost:5000/api/quickscan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: input }),
      });

      const scanData = await scanRes.json();

      if (!scanData.success) {
        setError(scanData.error);
        setIsScanning(false);
        return;
      }

      setResults(scanData.data);

      // 🔹 STEP 2: Generate AI Summary
      setIsGeneratingReport(true);

      const aiRes = await fetch("http://localhost:5000/api/ai-report", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scanType: "Quick Scan",
          scanData: scanData.data,
        }),
      });

      const aiData = await aiRes.json();

      if (!aiData.success) {
        setError("AI report generation failed");
      } else {
        setAiReport(aiData.aiReport);
      }
    } catch (err) {
      setError("Server unreachable");
    }

    setIsScanning(false);
    setIsGeneratingReport(false);
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

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="bg-gray-800 p-5 rounded-xl flex gap-4 shadow">
            <FaBug className="text-red-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Basic Vulnerability Detection</h4>
              <p className="text-gray-400 text-sm">
                Checks outdated headers, weak SSL, misconfigurations.
              </p>
            </div>
          </div>

          <div className="bg-gray-800 p-5 rounded-xl flex gap-4 shadow">
            <FaShieldAlt className="text-green-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Security Headers</h4>
              <p className="text-gray-400 text-sm">
                CSP, X-Frame-Options, HSTS, XSS Protection.
              </p>
            </div>
          </div>

          <div className="bg-gray-800 p-5 rounded-xl flex gap-4 shadow">
            <FaExclamationTriangle className="text-yellow-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Open Ports Snapshot</h4>
              <p className="text-gray-400 text-sm">
                Common exposed services and ports.
              </p>
            </div>
          </div>

          <div className="bg-gray-800 p-5 rounded-xl flex gap-4 shadow">
            <FaSearch className="text-blue-400 text-3xl mt-1" />
            <div>
              <h4 className="text-lg font-semibold">Exposure Checks</h4>
              <p className="text-gray-400 text-sm">
                DNS, IP exposure, technology fingerprinting.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Input */}
      <div className="flex flex-col items-center mt-14 px-4">
        <div className="bg-gray-800 p-6 rounded-2xl shadow-xl w-full max-w-xl">
          <label className="text-lg font-semibold">Enter URL</label>

          <input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="example.com"
            className="w-full mt-3 px-4 py-3 rounded-md bg-gray-700 text-white border border-gray-600"
          />

          <button
            onClick={handleScan}
            className="mt-5 flex items-center justify-center w-full bg-indigo-600 hover:bg-indigo-700 py-3 rounded-md font-semibold"
          >
            <FaSearch className="mr-2" />
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
        </div>
      )}

      {/* AI Report Loader */}
      {isGeneratingReport && (
        <div className="mt-12 text-center animate-pulse">
          <h2 className="text-2xl font-semibold text-indigo-400">
            Generating Security Summary...
          </h2>
        </div>
      )}

      {/* AI Summary */}
      {aiReport && (
        <div className="mt-16 px-4">
        <div className="bg-white border border-gray-200 rounded-2xl p-8 shadow-lg">
        <h2 className="text-3xl font-bold text-indigo-700 mb-6">
          AI Security Summary
        </h2>

        <div className="space-y-4">
          {formatAIReport(aiReport)}
        </div>
        </div>

        </div>
)}


      {/* Raw Results (unchanged) */}
      {scanDone && results && (
        <div className="mt-16 px-4 mb-20">
          <div className="bg-gray-800 p-6 rounded-2xl shadow-xl max-w-3xl mx-auto">
            <h2 className="text-3xl font-bold text-green-400 mb-3">
              Quick Scan Raw Results
            </h2>

            <pre className="bg-black p-4 rounded-lg text-green-400 text-sm whitespace-pre-wrap">
              {JSON.stringify(results, null, 2)}
            </pre>

            <button className="mt-6 flex items-center mx-auto bg-green-600 hover:bg-green-700 py-3 px-6 rounded-md font-semibold">
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
