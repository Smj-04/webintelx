// Password-hardener/frontend/src/components/Navbar.jsx
// WHITE THEME VERSION

import { NavLink } from "react-router-dom";

export default function Navbar() {
  return (
    <nav className="navbar">
      <a href="/" className="nav-logo" style={{ textDecoration: "none" }}>
        <svg viewBox="0 0 36 36" width="36" height="36" className="nav-logo-hex">
          <polygon points="18,2 34,11 34,25 18,34 2,25 2,11" fill="none" stroke="#c0392b" strokeWidth="1.5" />
          <polygon points="18,8 28,14 28,22 18,28 8,22 8,14" fill="none" stroke="#c0392b" strokeWidth="0.7" opacity="0.35" />
          <circle cx="18" cy="18" r="2.5" fill="#c0392b">
            <animate attributeName="opacity" values="1;0.4;1" dur="2.5s" repeatCount="indefinite" />
          </circle>
        </svg>
        <div className="nav-logo-text">
          <div className="nav-logo-title">WEBINTELX</div>
          <div className="nav-logo-sub">PASSWORD MODULE</div>
        </div>
      </a>

      <div className="nav-center">
        <NavLink to="/analyzer"  className={({ isActive }) => `nav-tab${isActive ? " active" : ""}`}>ANALYZER</NavLink>
        <NavLink to="/generator" className={({ isActive }) => `nav-tab${isActive ? " active" : ""}`}>GENERATOR</NavLink>
      </div>

      <div className="nav-status">
        <span className="nav-status-text" style={{ marginRight: 2 }}>MODULE_02</span>
        <div className="nav-dot" />
        <span className="nav-status-text">READY</span>
      </div>
    </nav>
  );
}