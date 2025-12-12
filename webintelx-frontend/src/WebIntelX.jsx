import React from 'react';
import { useNavigate } from 'react-router-dom';
import { FaSearch, FaUserSecret, FaBug, FaShieldAlt } from 'react-icons/fa';

export default function Home() {
  const navigate = useNavigate();

  const scanOptions = [
    {
      name: 'Quick Scan',
      description:
        'Run a fast reconnaissance and vulnerability scan on a single domain for instant insights.',
      icon: <FaSearch className="text-4xl" />,
      path: '/quick',
    },
    {
      name: 'Full Scan',
      description:
        'Perform a complete OSINT, reconnaissance, and vulnerability assessment with AI-based reporting.',
      icon: <FaUserSecret className="text-4xl" />,
      path: '/full',
    },
    {
      name: 'Custom Scan',
      description:
        'Select specific modules and customize the scanning workflow according to your testing needs.',
      icon: <FaBug className="text-4xl" />,
      path: '/custom',
    },
    {
      name: 'Phishing Detection',
      description:
        'Analyze suspicious URLs or domains for phishing patterns using heuristics and reputation analysis.',
      icon: <FaShieldAlt className="text-4xl" />,
      path: '/phishing',
    },
  ];

  return (
    <div className="min-h-screen bg-gray-50">
      {/* Hero Section */}
      <section className="relative text-center py-20 bg-gradient-to-r from-indigo-600 via-purple-600 to-pink-600 text-white overflow-hidden">
        <div className="relative max-w-4xl mx-auto px-4">
          <h1 className="text-4xl md:text-5xl font-extrabold mb-4">
            WebIntelX — Unified Web Intelligence
          </h1>
          <p className="text-lg md:text-xl max-w-2xl mx-auto text-white/90">
            Discover, analyze, and secure web assets with combined OSINT, recon, vulnerability scanning, and phishing detection.
          </p>

          <div className="mt-8 flex justify-center gap-4 flex-wrap">
            <button
              onClick={() => navigate('/quick')}
              className="px-6 py-3 bg-white text-indigo-700 rounded-full font-semibold shadow hover:scale-105 transform transition"
            >
              Start Quick Scan
            </button>

            <button
              onClick={() => navigate('/phishing')}
              className="px-6 py-3 bg-transparent border border-white/30 text-white rounded-full font-semibold hover:bg-white/10 transition"
            >
              Phishing Detection
            </button>
          </div>
        </div>
      </section>

      {/* Scan Option Cards */}
      <section className="py-16 max-w-6xl mx-auto px-4 -mt-12">
        <h2 className="text-3xl font-semibold text-center mb-8">Choose a Scan</h2>

        <div className="grid gap-8 grid-cols-1 md:grid-cols-4">
          {scanOptions.map((scan) => (
            <div
              key={scan.name}
              className="bg-white rounded-2xl shadow-lg p-6 flex flex-col items-center text-center hover:shadow-2xl transform hover:-translate-y-1 transition"
            >
              <div className="w-16 h-16 flex items-center justify-center bg-gray-100 rounded-full mb-4">
                {scan.icon}
              </div>

              <h3 className="text-lg font-bold">{scan.name}</h3>
              <p className="mt-2 text-sm text-gray-600">{scan.description}</p>

              <div className="mt-6">
                <button
                  onClick={() => navigate(scan.path)}
                  className="px-4 py-2 bg-indigo-600 text-white rounded-full text-sm font-medium hover:bg-indigo-700 transition"
                >
                  Start
                </button>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Footer */}
      <footer className="py-8 text-center">
        <p className="text-gray-700 mb-3">
          Ready to run a scan or check a suspicious URL?
        </p>
        <div className="flex justify-center gap-3">
          <button
            onClick={() => navigate('/phishing')}
            className="px-6 py-3 bg-red-600 text-white rounded-full hover:bg-red-700 transition"
          >
            Check URL (Phishing)
          </button>
          <button
            onClick={() => navigate('/quick')}
            className="px-6 py-3 bg-indigo-600 text-white rounded-full hover:bg-indigo-700 transition"
          >
            Run Quick Scan
          </button>
        </div>
      </footer>
    </div>
  );
}
