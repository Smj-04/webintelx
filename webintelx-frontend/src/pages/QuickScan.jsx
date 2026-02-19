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

  // ==========================
  // 🔹 CORE SECURITY SIGNALS
  // ==========================

  // Attack surface exposure
  if (data?.securityTrails?.risk === "HIGH") score += 2;
  if (data?.securityTrails?.risk === "MEDIUM") score += 1;

  // Exposed endpoints
  if (data?.endpoints?.length > 30) score += 2;
  else if (data?.endpoints?.length > 15) score += 1;

  // Legacy backend
  if (data?.headers?.["x-powered-by"]?.includes("PHP/5")) score += 2;

  // SSL issue
  if (data?.ssl?.error) score += 1;

  // ==========================
  // 🔹 INFRASTRUCTURE SIGNALS
  // ==========================

  // DNS failure
  if (!data?.dns) score += 1;

  // WHOIS missing
  if (!data?.whois) score += 1;

  // No ping response
  if (!data?.ping) score += 1;

  // Traceroute blocked (possible filtering / instability)
  if (!data?.traceroute || data.traceroute.length === 0) score += 1;

  // Email / domain reputation
  if (data?.emailReputation?.risk === "HIGH") score += 2;
  if (data?.emailReputation?.risk === "MEDIUM") score += 1;

  // ==========================
  // 🔹 FINAL CLASSIFICATION
  // ==========================

  if (score >= 8) return "CRITICAL";
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

  // =======================
// 🔹 URL FORMAT VALIDATION
// =======================

const isValidURL = (url) => {
  try {
    const formatted = url.startsWith("http")
      ? url
      : `http://${url}`;
    new URL(formatted);
    return true;
  } catch {
    return false;
  }
};

  const handleScan = async () => {
    if (!input.trim()) {
      return alert("Please enter a URL");
    }

    if (!isValidURL(input)) {
      return alert("Invalid URL format");
    }

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
  <div className="min-h-screen bg-[#0f172a] text-white relative overflow-hidden flex flex-col">

    {/* GRID BACKGROUND */}
    <div className="absolute inset-0 bg-[linear-gradient(rgba(56,189,248,0.05)_1px,transparent_1px),linear-gradient(90deg,rgba(56,189,248,0.05)_1px,transparent_1px)] bg-[size:40px_40px] opacity-30"></div>

    {/* HEADER */}
    <div className="relative z-10 text-center py-20">
      <h1 className="text-5xl font-extrabold mb-4 bg-gradient-to-r from-white to-slate-400 bg-clip-text text-transparent">
        Quick Scan
      </h1>
      <p className="text-slate-400 text-lg max-w-2xl mx-auto">
        High-level security snapshot to identify immediate risks.
      </p>
    </div>

    {/* INPUT CARD */}
    <div className="relative z-10 flex justify-center px-4">
      <div className="bg-slate-800/60 backdrop-blur-md border border-slate-700 p-8 rounded-2xl shadow-xl w-full max-w-xl">

        <label className="text-lg font-semibold text-slate-200">
          Target URL
        </label>

        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="example.com"
          className="w-full mt-4 px-4 py-3 rounded-lg bg-slate-900 border border-slate-700 focus:border-sky-400 outline-none text-white"
        />

        <button
          onClick={handleScan}
          className="mt-6 flex items-center justify-center w-full bg-sky-500 hover:bg-sky-400 text-black py-3 rounded-lg font-semibold transition shadow-lg shadow-sky-500/20"
        >
          <FaSearch className="mr-2" />
          Start Quick Scan
        </button>

        {error && <p className="text-red-400 mt-4">{error}</p>}
      </div>
    </div>

    {/* LOADER */}
    {isScanning && (
      <div className="relative z-10 mt-16 text-center animate-pulse">
        <h2 className="text-2xl font-semibold text-sky-400">
          Running security checks…
        </h2>
      </div>
    )}

    {/* RESULTS */}
    {scanDone && results && (
      <div className="relative z-10 mt-20 px-4 max-w-7xl mx-auto">

        <div className="bg-slate-900/80 border border-slate-700 rounded-2xl p-10">

          {/* OVERALL RISK */}
          <h2 className="text-3xl font-bold mb-6">
            Overall Risk Assessment
          </h2>

          <div
            className={`inline-block mb-10 px-6 py-3 text-xl font-extrabold rounded ${
              riskColor(overallRisk)
            }`}
          >
            {overallRisk} RISK
          </div>

          {/* CORE SECURITY SUMMARY */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">

            <SummaryCard
              title="Attack Surface (SecurityTrails)"
              icon={<FaSearch className="text-sky-400" />}
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
                `Unique parameters detected: ${
                  new Set(results.endpoints.map((e) => e.param)).size
                }`,
                `Example endpoint: ${
                  results.endpoints[0]?.url || "N/A"
                }`,
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
              icon={<FaExclamationTriangle className="text-yellow-400" />}
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

          {/* INFRASTRUCTURE INTELLIGENCE */}
  <h2 className="text-2xl font-bold mt-16 mb-8">
    Infrastructure Intelligence
  </h2>

  <div className="grid grid-cols-1 md:grid-cols-2 gap-8">

    {/* DNS */}
    <SummaryCard
      title="DNS Intelligence"
      icon={<FaSearch className="text-sky-400" />}
      summary={
        results.dns
          ? "DNS records resolved successfully"
          : "DNS resolution failed"
      }
      risk={!results.dns ? "MEDIUM" : "LOW"}
      details={
        results.dns
          ? [
              `A Records: ${
                results.dns.A?.length || 0
              }`,
              `Primary IP: ${
                results.dns.A?.[0] || "N/A"
              }`,
            ]
          : ["No DNS response received"]
      }
    />

    {/* WHOIS */}
    <SummaryCard
      title="WHOIS Information"
      icon={<FaShieldAlt className="text-indigo-400" />}
      summary="Domain registration metadata"
      risk={!results.whois ? "MEDIUM" : "LOW"}
      details={
        results.whois
          ? [
              `Registrar: ${
                results.whois.registrar || "Unknown"
              }`,
              `Created: ${
                results.whois.creationDate || "N/A"
              }`,
            ]
          : ["WHOIS information unavailable"]
      }
    />

    {/* TRACEROUTE */}
    <SummaryCard
      title="Network Path (Traceroute)"
      icon={<FaExclamationTriangle className="text-yellow-400" />}
      summary={`${results.traceroute?.length || 0} network hops identified`}
      risk={
        results.traceroute?.length > 25
          ? "MEDIUM"
          : "LOW"
      }
      details={
        results.traceroute
          ? [
              `Final Hop: ${
                results.traceroute[
                  results.traceroute.length - 1
                ]?.ip || "Unknown"
              }`,
              `Total Hops: ${results.traceroute.length}`,
            ]
          : ["Traceroute blocked or unavailable"]
      }
    />

    {/* PING */}
    <SummaryCard
      title="Host Reachability (Ping)"
      icon={<FaBug className="text-green-400" />}
      summary={
        results.ping
          ? "Host responded to ICMP echo requests"
          : "No ICMP response"
      }
      risk={!results.ping ? "MEDIUM" : "LOW"}
      details={
        results.ping
          ? [
              `Average Latency: ${
                results.ping.avgTime || "N/A"
              } ms`,
              `Packet Loss: ${
                results.ping.packetLoss || "0%"
              }`,
            ]
          : ["ICMP echo disabled or filtered"]
      }
    />

    {/* EMAIL REPUTATION */}
    <SummaryCard
      title="Email / Domain Reputation"
      icon={<FaBug className="text-purple-400" />}
      summary={`Reputation level: ${
        results.emailReputation?.risk || "Unknown"
      }`}
      risk={results.emailReputation?.risk || "LOW"}
      details={[
        results.emailReputation?.note ||
          "No significant abuse indicators detected",
      ]}
    />

  </div>


          {/* PDF DOWNLOAD */}
          <div className="mt-14 text-center">
            <button
              onClick={downloadPDF}
              disabled={isDownloading}
              className={`flex items-center mx-auto py-3 px-8 rounded-lg font-semibold transition ${
                isDownloading
                  ? "bg-slate-700 cursor-not-allowed"
                  : "bg-sky-500 hover:bg-sky-400 text-black shadow-lg shadow-sky-500/20"
              }`}
            >
              <FaFileDownload className="mr-2" />
              {isDownloading
                ? "Preparing PDF…"
                : "Download Detailed PDF Report"}
            </button>

            <p className="text-slate-400 text-sm mt-3">
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
