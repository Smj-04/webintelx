import { useState } from "react";
import {
  FaSearch,
  FaBug,
  FaShieldAlt,
  FaExclamationTriangle,
  FaFileDownload,
} from "react-icons/fa";
import Footer from "../components/Footer";

/* =======================
   🔹 RISK HELPERS
======================= */

const calculateOverallRisk = (data) => {
  let score = 0;

  if (data?.securityTrails?.risk === "HIGH") score += 3;
  if (data?.securityTrails?.risk === "MEDIUM") score += 2;

  if (data?.endpoints?.length > 20) score += 3;
  else if (data?.endpoints?.length > 10) score += 2;

  if (data?.headers?.["x-powered-by"]?.includes("PHP/5")) score += 2;

  if (data?.ssl?.error) score += 1;

  if (score >= 7) return "CRITICAL";
  if (score >= 5) return "HIGH";
  if (score >= 3) return "MEDIUM";
  return "LOW";
};

const riskColor = (risk) => {
  if (risk === "CRITICAL") return "text-red-700 bg-red-100";
  if (risk === "HIGH") return "text-red-600 bg-red-100";
  if (risk === "MEDIUM") return "text-yellow-700 bg-yellow-100";
  return "text-green-700 bg-green-100";
};

/* =======================
   🔹 SUMMARY CARD
======================= */

const SummaryCard = ({ title, icon, summary, risk, details = [] }) => (
  <div className="bg-gray-800 p-5 rounded-xl shadow flex gap-4">
    <div className="text-3xl">{icon}</div>

    <div className="flex-1">
      <h4 className="text-lg font-semibold">{title}</h4>
      <p className="text-gray-400 text-sm mt-1">{summary}</p>

      {details.length > 0 && (
        <ul className="mt-3 text-sm text-gray-300 list-disc list-inside space-y-1">
          {details.map((d, i) => (
            <li key={i}>{d}</li>
          ))}
        </ul>
      )}

      {risk && (
        <span
          className={`inline-block mt-3 px-3 py-1 text-xs font-bold rounded ${riskColor(
            risk
          )}`}
        >
          {risk}
        </span>
      )}
    </div>
  </div>
);

/* =======================
   🔹 MAIN COMPONENT
======================= */

export default function QuickScan() {
  const [input, setInput] = useState("");
  const [isScanning, setIsScanning] = useState(false);
  const [scanDone, setScanDone] = useState(false);
  const [results, setResults] = useState(null);
  const [error, setError] = useState("");
  const [isDownloading, setIsDownloading] = useState(false);

  const handleScan = async () => {
    if (!input.trim()) return alert("Please enter a URL");

    setIsScanning(true);
    setError("");
    setResults(null);
    setScanDone(false);

    try {
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
      setScanDone(true);
    } catch (err) {
      setError("Server unreachable");
    }

    setIsScanning(false);
  };

  /* =======================
     📄 PDF DOWNLOAD HANDLER
  ======================= */

  const downloadPDF = async () => {
    if (!results) return;

    setIsDownloading(true);

    try {
      const res = await fetch(
        "http://localhost:5000/api/report/quickscan/pdf",
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            target: input,
            scanData: results,
          }),
        }
      );

      if (!res.ok) throw new Error("PDF generation failed");

      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);

      const a = document.createElement("a");
      a.href = url;
      a.download = `QuickScan-${input.replace(/[^a-z0-9]/gi, "_")}.pdf`;
      a.click();

      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert("Failed to download PDF report");
    }

    setIsDownloading(false);
  };

  const overallRisk = results ? calculateOverallRisk(results) : null;

  return (
    <div className="min-h-screen bg-gray-900 text-white flex flex-col">
      {/* Header */}
      <div className="text-center py-16 bg-gradient-to-r from-purple-600 to-indigo-600 shadow-lg">
        <h1 className="text-4xl font-extrabold mb-3">Quick Scan</h1>
        <p className="text-gray-200 text-lg max-w-2xl mx-auto">
          High-level security snapshot to identify immediate risks.
        </p>
      </div>

      {/* Input */}
      <div className="flex flex-col items-center mt-12 px-4">
        <div className="bg-gray-800 p-6 rounded-2xl shadow-xl w-full max-w-xl">
          <label className="text-lg font-semibold">Target URL</label>

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
            Running security checks…
          </h2>
        </div>
      )}

      {/* OVERALL SUMMARY */}
      {scanDone && results && (
        <div className="mt-16 px-4 max-w-6xl mx-auto">
          <div className="bg-gray-900 border border-gray-700 rounded-2xl p-8">
            <h2 className="text-3xl font-bold mb-6">
              Overall Risk Assessment
            </h2>

            <div
              className={`inline-block mb-8 px-6 py-3 text-xl font-extrabold rounded ${riskColor(
                overallRisk
              )}`}
            >
              {overallRisk} RISK
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <SummaryCard
                title="Attack Surface (SecurityTrails)"
                icon={<FaSearch className="text-blue-400" />}
                summary={`${results.securityTrails.subdomainCount} subdomains discovered`}
                risk={results.securityTrails.risk}
                details={[
                  `Examples: ${results.securityTrails.subdomains
                    .slice(0, 3)
                    .join(", ")}`,
                  "Large historical DNS footprint detected",
                ]}
              />

              <SummaryCard
                title="Exposed Endpoints"
                icon={<FaBug className="text-red-400" />}
                summary={`${results.endpoints.length} parameterized URLs found`}
                risk={
                  results.endpoints.length > 20
                    ? "HIGH"
                    : results.endpoints.length > 10
                    ? "MEDIUM"
                    : "LOW"
                }
                details={[
                  `Common params: ${[
                    ...new Set(results.endpoints.map((e) => e.param)),
                  ]
                    .slice(0, 4)
                    .join(", ")}`,
                  "Potential SQLi / XSS surface",
                ]}
              />

              <SummaryCard
                title="Technology Stack"
                icon={<FaShieldAlt className="text-green-400" />}
                summary={`Server: ${results.headers.server}`}
                risk={
                  results.headers["x-powered-by"]?.includes("PHP/5")
                    ? "HIGH"
                    : "LOW"
                }
                details={[
                  `Backend: ${
                    results.headers["x-powered-by"] || "Unknown"
                  }`,
                  "Legacy stack increases exploit likelihood",
                ]}
              />

              <SummaryCard
                title="Network & Transport"
                icon={
                  <FaExclamationTriangle className="text-yellow-400" />
                }
                summary={`Open ports: ${results.openPorts.length}`}
                risk={results.ssl.error ? "MEDIUM" : "LOW"}
                details={[
                  results.ssl.error
                    ? "HTTPS not enforced"
                    : "TLS enabled",
                  results.openPorts.length
                    ? `Ports: ${results.openPorts
                        .map((p) => p.port)
                        .join(", ")}`
                    : "No common ports exposed",
                ]}
              />
            </div>

            {/* PDF BUTTON */}
            <div className="mt-10 text-center">
              <button
                onClick={downloadPDF}
                disabled={isDownloading}
                className={`flex items-center mx-auto py-3 px-8 rounded-md font-semibold ${
                  isDownloading
                    ? "bg-gray-600 cursor-not-allowed"
                    : "bg-indigo-600 hover:bg-indigo-700"
                }`}
              >
                <FaFileDownload className="mr-2" />
                {isDownloading
                  ? "Preparing PDF…"
                  : "Download Detailed PDF Report"}
              </button>

              <p className="text-gray-400 text-sm mt-2">
                Includes full findings, evidence & remediation guidance
              </p>
            </div>
          </div>
        </div>
      )}

      <Footer />
    </div>
  );
}
