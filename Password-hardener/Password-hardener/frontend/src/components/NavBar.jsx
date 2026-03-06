import { NavLink, useLocation } from "react-router-dom";

export default function Navbar() {
  const loc = useLocation();

  return (
    <nav className="navbar">
      {/* Logo */}
      <a href="/" className="nav-logo" style={{ textDecoration: "none" }}>
        <svg className="nav-logo-hex" viewBox="0 0 36 36">
          <polygon points="18,2 34,11 34,25 18,34 2,25 2,11" fill="none" stroke="#00d4ff" strokeWidth="1.5" />
          <polygon points="18,8 28,14 28,22 18,28 8,22 8,14" fill="none" stroke="#00d4ff" strokeWidth="0.7" opacity="0.4" />
          <circle cx="18" cy="18" r="2.5" fill="#00d4ff">
            <animate attributeName="opacity" values="1;0.5;1" dur="2.5s" repeatCount="indefinite" />
          </circle>
        </svg>
        <div className="nav-logo-text">
          <div className="nav-logo-title">WEBINTELX</div>
          <div className="nav-logo-sub">PASSWORD MODULE</div>
        </div>
      </a>

      {/* Tabs */}
      <div className="nav-center">
        <NavLink
          to="/analyzer"
          className={({ isActive }) => `nav-tab${isActive ? " active" : ""}`}
        >
          ANALYZER
        </NavLink>
        <NavLink
          to="/generator"
          className={({ isActive }) => `nav-tab${isActive ? " active" : ""}`}
        >
          GENERATOR
        </NavLink>
      </div>

      {/* Status */}
      <div className="nav-status">
        <span className="nav-status-text" style={{ marginRight: 2 }}>MODULE_02</span>
        <div className="nav-dot" />
        <span className="nav-status-text">READY</span>
      </div>
    </nav>
  );
}