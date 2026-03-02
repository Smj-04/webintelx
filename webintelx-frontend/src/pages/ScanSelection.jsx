import React from "react";
import { useNavigate } from "react-router-dom";

export default function ScanSelection() {
  const navigate = useNavigate();

  const wrapperStyle = {
    minHeight: "100vh",
    background: "#0f172a", // solid dark blue    
    color: "white",
    padding: "80px 20px",
    textAlign: "center",
  };

  const gridStyle = {
    display: "grid",
    gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
    gap: "24px",
    maxWidth: "1000px",
    margin: "50px auto 0 auto",
  };

  const cardStyle = {
    background: "rgba(255,255,255,0.04)",
    border: "1px solid rgba(255,255,255,0.08)",
    padding: "30px",
    borderRadius: "16px",
    cursor: "pointer",
    transition: "all 0.3s ease",
  };

  const hoverStyle = {
    transform: "translateY(-6px)",
    border: "1px solid #38bdf8",
  };

  return (
  <div
    style={{
      minHeight: "100vh",
      background: "radial-gradient(circle at top, #0f172a, #020617)",
      padding: "80px 20px",
      color: "white",
    }}
  >
    {/* CONTAINER */}
    <div
      style={{
        maxWidth: "1200px",
        margin: "0 auto",
        background: "rgba(255,255,255,0.03)",
        border: "1px solid rgba(255,255,255,0.08)",
        borderRadius: "24px",
        padding: "40px",
        backdropFilter: "blur(14px)",
      }}
    >
      {/* HEADER */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "40px",
        }}
      >
        <div>
          <h2 style={{ fontSize: "22px", marginBottom: "6px" }}>
            Choose your scan mode
          </h2>
          <p style={{ opacity: 0.6 }}>
            Select how deep you want WebIntelX to probe your target surface.
          </p>
        </div>

        <div style={{ color: "#38bdf8", fontSize: "14px" }}>
          ● Scanner idle • Ready to launch
        </div>
      </div>

      {/* SCAN CARDS ROW */}
      <div
        style={{
          display: "flex",
          gap: "20px",
          flexWrap: "wrap",
        }}
      >
        {[
          {
            title: "Quick Scan",
            subtitle: "~ 2 minutes • Surface checks",
            desc: "Recon + OSINT",
            route: "/quick",
          },
          {
            title: "Full Scan",
            subtitle: "2-15 minutes • Deep coverage",
            desc: "Active Vulnerability Scanning",
            route: "/full",
          },
          
        ].map((mode, index) => (
          <div
            key={index}
            onClick={() => navigate(mode.route)}
            style={{
              flex: "1 1 250px",
              background: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.08)",
              padding: "24px",
              borderRadius: "16px",
              cursor: "pointer",
              transition: "all 0.3s ease",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.transform = "translateY(-6px)";
              e.currentTarget.style.borderColor = "#38bdf8";
              e.currentTarget.style.boxShadow =
                "0 20px 40px rgba(56,189,248,0.2)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.transform = "translateY(0)";
              e.currentTarget.style.borderColor =
                "rgba(255,255,255,0.08)";
              e.currentTarget.style.boxShadow = "none";
            }}
          >
            <h3 style={{ marginBottom: "6px" }}>{mode.title}</h3>
            <div
              style={{
                fontSize: "12px",
                background: "rgba(56,189,248,0.15)",
                padding: "4px 10px",
                borderRadius: "20px",
                display: "inline-block",
                marginBottom: "14px",
              }}
            >
              {mode.subtitle}
            </div>
            <p style={{ opacity: 0.6, fontSize: "13px" }}>
              {mode.desc}
            </p>
          </div>
        ))}
      </div>
    </div>
  </div>
);
}