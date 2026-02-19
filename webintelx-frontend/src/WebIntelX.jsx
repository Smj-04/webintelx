import React from "react";
import { useNavigate } from "react-router-dom";
import "./Home.css";

export default function Home() {
  const navigate = useNavigate();

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
            <a className="nav-item">Scan Modes</a>
            <a className="nav-item">Live Map</a>
            <a className="nav-item">Reports</a>
            <a className="nav-item">Settings</a>
          </div>


        </nav>

        {/* MAIN CONTENT */}
        <main className="main-content">
          {/* HERO */}
          <section className="hero-section">
            <div className="hero-badge">
              <iconify-icon icon="lucide:sparkles" style={{ fontSize: "14px" }} />
              <span>v2.4 Now Live: AI-Powered Risk Assessment</span>
            </div>

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
                onClick={() => navigate("/quick")}
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

          {/* SCAN OPTIONS */}
          <section className="scan-options">
            <div className="scan-options-header">
              <div>
                <div className="scan-options-title">
                  Choose your scan mode
                </div>
                <div className="scan-options-subtitle">
                  Select how deep you want WebIntelX to probe your target surface.
                </div>
              </div>
              <div className="scan-options-indicator">
                <span className="scan-dot"></span>
                <span>Scanner idle • Ready to launch</span>
              </div>
            </div>

            <div className="scan-options-grid">
              <div
                className="scan-option-card"
                onClick={() => navigate("/quick")}
              >
                <div className="scan-option-inner">
                  <div className="scan-option-top">
                    <div>
                      <div className="scan-option-label">Quick Scan</div>
                      <div className="scan-option-tag">
                        ~ 2 minutes • Surface checks
                      </div>
                    </div>
                    <div className="scan-option-icon">
                      <iconify-icon icon="lucide:radar" style={{ fontSize: "18px" }} />
                    </div>
                  </div>
                  <div className="scan-option-meta">
                    <span>Best for: instant health check</span>
                    <span>Last used 5m ago</span>
                  </div>
                </div>
              </div>

              <div
                className="scan-option-card"
                onClick={() => navigate("/full")}
              >
                <div className="scan-option-inner">
                  <div className="scan-option-top">
                    <div>
                      <div className="scan-option-label">Full Scan</div>
                      <div className="scan-option-tag">
                        45-90 minutes • Deep coverage
                      </div>
                    </div>
                    <div className="scan-option-icon">
                      <iconify-icon icon="lucide:scan-line" style={{ fontSize: "18px" }} />
                    </div>
                  </div>
                  <div className="scan-option-meta">
                    <span>Recon + OSINT + CVE sweep</span>
                    <span>Recommended weekly</span>
                  </div>
                </div>
              </div>

              <div
                className="scan-option-card"
                onClick={() => navigate("/custom")}
              >
                <div className="scan-option-inner">
                  <div className="scan-option-top">
                    <div>
                      <div className="scan-option-label">Custom Scan</div>
                      <div className="scan-option-tag">
                        Fine-grained controls
                      </div>
                    </div>
                    <div className="scan-option-icon">
                      <iconify-icon icon="lucide:settings-2" style={{ fontSize: "18px" }} />
                    </div>
                  </div>
                  <div className="scan-option-meta">
                    <span>Targeted ports, tech, scopes</span>
                    <span>Templates available</span>
                  </div>
                </div>
              </div>

              <div
                className="scan-option-card"
                onClick={() => navigate("/phishing")}
              >
                <div className="scan-option-inner">
                  <div className="scan-option-top">
                    <div>
                      <div className="scan-option-label">Password Checker</div>
                      <div className="scan-option-tag">
                        Credential exposure audit
                      </div>
                    </div>
                    <div className="scan-option-icon">
                      <iconify-icon icon="lucide:key-round" style={{ fontSize: "18px" }} />
                    </div>
                  </div>
                  <div className="scan-option-meta">
                    <span>HIBP-style breach lookup</span>
                    <span>Safe & hashed locally</span>
                  </div>
                </div>
              </div>
            </div>
          </section>

          {/* FEATURES */}
          <section className="features-grid">
            <div className="feature-card">
              <div className="feature-icon-wrapper">
                <iconify-icon icon="lucide:radar" style={{ fontSize: "24px" }} />
              </div>
              <h3 className="feature-title">Reconnaissance</h3>
              <p className="feature-desc">
                Automated sub-domain enumeration and port scanning to map your entire attack surface instantly.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrapper">
                <iconify-icon icon="lucide:globe" style={{ fontSize: "24px" }} />
              </div>
              <h3 className="feature-title">OSINT Analysis</h3>
              <p className="feature-desc">
                Deep web scraping and public record correlation to identify exposed assets and data leaks.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrapper">
                <iconify-icon icon="lucide:shield-alert" style={{ fontSize: "24px" }} />
              </div>
              <h3 className="feature-title">Vulnerability Scan</h3>
              <p className="feature-desc">
                Continuous security testing against CVE databases to detect critical weaknesses before exploitation.
              </p>
            </div>

            <div className="feature-card">
              <div className="feature-icon-wrapper">
                <iconify-icon icon="lucide:bot" style={{ fontSize: "24px" }} />
              </div>
              <h3 className="feature-title">AI Risk Reports</h3>
              <p className="feature-desc">
                Generative AI analysis of findings to prioritize threats and suggest remediation steps.
              </p>
            </div>
          </section>

          
        </main>
      </div>
    </div>
  );
}
