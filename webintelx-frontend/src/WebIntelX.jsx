import React, { useRef } from "react";
import { useNavigate } from "react-router-dom";
import "./Home.css";

export default function Home() {
  const navigate = useNavigate();
  const scanSectionRef = useRef(null);

  const scrollToScanSection = () => {
  scanSectionRef.current?.scrollIntoView({
    behavior: "smooth",
    block: "start",
  });
};

  return (
    <div
      className="export-wrapper"
      style={{
        width: "100%",
        maxWidth: "1440px",
        minHeight: "100vh",
        margin: "0 auto",
        position: "relative",
        fontFamily: "var(--font-family-body)",
        backgroundColor: "var(--background)",
      }}
    >

      <div className="app-wrapper">
        <div className="grid-pattern"></div>

        {/* NAVBAR */}
        <nav className="nav-bar">
          <div className="nav-brand">
            <div
              style={{
                width: "32px",
                height: "32px",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: "rgba(56, 189, 248, 0.2)",
                borderRadius: "8px",
              }}
              className="brand-icon"
            >
              <iconify-icon icon="lucide:shield-check" style={{ fontSize: "20px" }} />
            </div>
            WebIntelX
          </div>

          <div className="nav-links">
            <a className="nav-item">Dashboard</a>
            <a
            className="nav-item"
            onClick={scrollToScanSection}
            style={{ cursor: "pointer" }}
          >
            Action Selection
          </a>
        
          </div>


        </nav>

        {/* MAIN CONTENT */}
        <main className="main-content">
          {/* HERO */}
          <section className="hero-section">
         

            <h1 className="hero-title">
              Unified Web Intelligence & <br />
              Vulnerability Analysis
            </h1>

            <p className="hero-subtitle">
              The complete toolkit for modern security teams. Automated reconnaissance,
              deep OSINT gathering, and continuous vulnerability scanning in one platform.
            </p>

            <div className="hero-actions">
              <button
                className="btn btn-primary"
                onClick={() => navigate("/scan")}
              >
                <iconify-icon icon="lucide:play" style={{ fontSize: "18px" }} />
                Start Scan
              </button>

            </div>

            <div className="hero-meta">
              <span>Adaptive scan engine • Zero-touch scheduling</span>
              <span>Encrypted telemetry • SOC-ready exports</span>
            </div>
          </section>

          <div
            ref={scanSectionRef}
            style={{
              display: "flex",
              gap: "30px",
              justifyContent: "center",
              alignItems: "stretch",
              maxWidth: "1100px",
              margin: "0 auto",
              flexWrap: "wrap",
            }}
          >

            {/* START SCAN */}
            <div
              onClick={() => navigate("/scan")}
              style={{
                flex: "1 1 300px",
                background: "linear-gradient(135deg, #2563eb, #6366f1)",
                padding: "32px",
                borderRadius: "18px",
                cursor: "pointer",
                transition: "0.3s ease",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.transform = "translateY(-6px)")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.transform = "translateY(0)")
              }
            >
              <h3 style={{ fontSize: "20px", marginBottom: "12px" }}>
                Start Security Scan
              </h3>
              <p style={{ opacity: 0.9, fontSize: "14px", lineHeight: "1.6" }}>
                Launch reconnaissance, OSINT analysis and vulnerability testing
                from a unified scanning interface.
              </p>
              <div style={{ marginTop: "18px", fontWeight: "500" }}>
                Choose Scan Mode →
              </div>
            </div>

            {/* PASSWORD CHECKER */}
            <div
              onClick={() => window.location.href = "http://localhost:3001"}
              style={{
                flex: "1 1 300px",
                background: "rgba(255,255,255,0.04)",
                border: "1px solid rgba(255,255,255,0.08)",
                padding: "32px",
                borderRadius: "18px",
                cursor: "pointer",
                transition: "0.3s ease",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.transform = "translateY(-6px)")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.transform = "translateY(0)")
              }
            >
              <h3 style={{ fontSize: "20px", marginBottom: "12px" }}>
                Password Strength Checker
              </h3>
              <p style={{ opacity: 0.7, fontSize: "14px", lineHeight: "1.6" }}>
                Check password strength and exposure against breach databases.
              </p>
              <div style={{ marginTop: "18px", fontWeight: "500" }}>
                Analyze Password →
              </div>
            </div>

            {/* PHISHING DETECTION */}
            <div
              onClick={() => navigate("/phishing")}
              style={{
                flex: "1 1 300px",
                background: "rgba(255,255,255,0.04)",
                border: "1px solid rgba(255,255,255,0.08)",
                padding: "32px",
                borderRadius: "18px",
                cursor: "pointer",
                transition: "0.3s ease",
              }}
              onMouseEnter={(e) =>
                (e.currentTarget.style.transform = "translateY(-6px)")
              }
              onMouseLeave={(e) =>
                (e.currentTarget.style.transform = "translateY(0)")
              }
            >
              <h3 style={{ fontSize: "20px", marginBottom: "12px" }}>
                Phishing Site Detection
              </h3>
              <p style={{ opacity: 0.7, fontSize: "14px", lineHeight: "1.6" }}>
                Detect malicious or spoofed websites using intelligent heuristics.
              </p>
              <div style={{ marginTop: "18px", fontWeight: "500" }}>
                Scan Website →
              </div>
            </div>
          </div>

          {/* FEATURES - PROFESSIONAL STACKED VERSION */}
          <section
            style={{
              marginTop: "120px",
              maxWidth: "1000px",
              marginLeft: "auto",
              marginRight: "auto",
              display: "flex",
              flexDirection: "column",
              gap: "40px",
              padding: "0 20px",
            }}
          >

            {/* RECON */}
            <div
              style={{
                background: "rgba(255,255,255,0.03)",
                border: "1px solid rgba(255,255,255,0.08)",
                padding: "40px",
                borderRadius: "20px",
              }}
            >
              <h2 style={{ fontSize: "22px", marginBottom: "14px" }}>
                🔍 Reconnaissance & Surface Mapping
              </h2>
              <p style={{ opacity: 0.75, lineHeight: "1.8" }}>
                Automated sub-domain enumeration, directory discovery,
                port scanning and technology fingerprinting to map your
                entire external attack surface with precision. 
                Designed to identify hidden assets before attackers do.
              </p>
            </div>

            {/* OSINT */}
            <div
              style={{
                background: "rgba(255,255,255,0.03)",
                border: "1px solid rgba(255,255,255,0.08)",
                padding: "40px",
                borderRadius: "20px",
              }}
            >
              <h2 style={{ fontSize: "22px", marginBottom: "14px" }}>
                🌐 OSINT Intelligence Correlation
              </h2>
              <p style={{ opacity: 0.75, lineHeight: "1.8" }}>
                Deep public record aggregation and breach database correlation
                to uncover exposed credentials, leaked assets and publicly
                accessible data tied to your organization.
                All findings are cross-validated for risk accuracy.
              </p>
            </div>

            {/* VULNERABILITY */}
            <div
              style={{
                background: "rgba(255,255,255,0.03)",
                border: "1px solid rgba(255,255,255,0.08)",
                padding: "40px",
                borderRadius: "20px",
              }}
            >
              <h2 style={{ fontSize: "22px", marginBottom: "14px" }}>
                🛡 Vulnerability Assessment Engine
              </h2>
              <p style={{ opacity: 0.75, lineHeight: "1.8" }}>
                Continuous security testing against CVE databases,
                injection flaws, misconfigurations and known exploit patterns.
                Active scanning modules validate real-world exploitability
                to reduce false positives.
              </p>
            </div>

          {/* CROSS VALIDATION */}
          <div
            style={{
              background: "rgba(255,255,255,0.03)",
              border: "1px solid rgba(255,255,255,0.08)",
              padding: "40px",
              borderRadius: "20px",
            }}
          >
            <h2 style={{ fontSize: "22px", marginBottom: "14px" }}>
              🧩 Cross-Validation & Threat Correlation
            </h2>
            <p style={{ opacity: 0.75, lineHeight: "1.8" }}>
              Findings from reconnaissance, OSINT intelligence, and vulnerability
              scanning are automatically correlated to identify high-risk assets.
              This layered validation reduces false positives and highlights
              exploitable attack paths across your infrastructure.
            </p>
          </div>
          </section>

          
        </main>
      </div>
    </div>
  );
}
