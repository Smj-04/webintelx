import React, { useState } from "react";
import axios from "axios";
import {
  FaShieldAlt,
  FaSearch,
  FaExclamationTriangle,
  FaLink,
  FaFileDownload,
} from "react-icons/fa";

export default function PhishingDetection() {
  const [url, setUrl] = useState("");
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);

  const startScan = async () => {
    if (!url.trim()) return;
  
    setLoading(true);
    setResults(null);
  
    try {
      const response = await axios.post(
        "http://localhost:5000/api/phishing-check",
        { url }
      );
  
      setResults(response.data);
    } catch (error) {
      setResults({
        error: "Phishing analysis failed",
      });
    }
  
    setLoading(false);
  };

  return (
    <div className="min-h-screen bg-gray-50 p-6 pt-16">
      {/* Header */}
      <h1 className="text-4xl font-bold text-center text-indigo-600 mb-8">
        Phishing Detection
      </h1>

      {/* Input Card */}
      <div className="max-w-3xl mx-auto bg-white shadow-lg rounded-2xl p-8">
        <h2 className="text-2xl font-semibold text-gray-800 flex items-center gap-2 mb-4">
          <FaShieldAlt className="text-indigo-500" /> Analyze URL / Domain
        </h2>

        <p className="text-gray-600 mb-4">
          Enter a suspicious link or domain to analyze phishing heuristics,
          domain reputation, SSL certificate signals, redirect behavior, and
          malicious indicators.
        </p>

        <div className="flex gap-3 mt-4">
          <input
            type="text"
            className="flex-1 px-4 py-3 rounded-xl border bg-white text-gray-900 placeholder-gray-400 focus:ring-2 focus:ring-indigo-400 focus:outline-none"            placeholder="https://example.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button
            onClick={startScan}
            className="px-6 py-3 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 transition"
          >
            Start Scan
          </button>
        </div>

        {/* Loading Indicator */}
        {loading && (
          <div className="text-center mt-6">
            <p className="text-indigo-600 font-semibold">Scanning...</p>
            <div className="animate-pulse mt-2 text-gray-400">
              Checking domain reputation, SSL certificate, redirects...
            </div>
          </div>
        )}
      </div>

      {/* What this scan checks */}
      <div className="max-w-4xl mx-auto mt-12">
        <h3 className="text-2xl font-semibold text-gray-800 mb-4 flex items-center gap-2">
          <FaSearch className="text-blue-500" /> What PhishingScan Checks
        </h3>

        <div className="grid md:grid-cols-2 gap-6">
          {[
            "SSL Certificate validity & mismatches",
            "URL obfuscation & encoded payloads",
            "Domain age & WHOIS abnormalities",
            "Redirect chains & malicious forwarding",
            "Typosquatting / lookalike domain patterns",
            "Suspicious JS, keyloggers, or iframes",
            "Google Safe Browsing & threat reputation",
            "Page impersonation heuristics (bank/login clones)",
          ].map((item) => (
            <div
              key={item}
              className="bg-white p-4 shadow rounded-xl flex items-start gap-3"
            >
              <FaExclamationTriangle className="text-red-500 mt-1" />
              <p className="text-gray-700">{item}</p>
            </div>
          ))}
        </div>
      </div>
      {/* Results Section */}
      {results && !results.error && (
        <div className="max-w-3xl mx-auto bg-white text-gray-900 shadow-xl rounded-2xl p-8 mt-12 border-t-4 border-indigo-600">          <h3 className="text-2xl font-bold text-gray-800 mb-4">
            Scan Results
          </h3>

          <p className="mb-2">
            <strong>Prediction:</strong> {results.prediction}
          </p>

          <p className="mb-2">
            <strong>Risk Level:</strong> {results.risk_level}
          </p>

          <p className="mb-2">
            <strong>Confidence:</strong>{" "}
            {(results.ml_probability * 100).toFixed(2)}%
          </p>

          <p className="mb-2">
            <strong>Details:</strong> {results.details}
          </p>
        </div>
      )}

      {results?.error && (
        <div className="text-red-600 mt-6 text-center font-semibold">
          {results.error}
        </div>
      )}

      <div className="h-10"></div>
    </div>
  );
}
