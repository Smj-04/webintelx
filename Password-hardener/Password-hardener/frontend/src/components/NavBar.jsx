import { Link, useLocation } from "react-router-dom";

export default function Navbar() {
  const location = useLocation();

  return (
    <nav className="navbar">
      <div className="nav-logo">Password Hardener</div>

      <div className="nav-links">
        <Link
          to="/analyzer"
          className={location.pathname === "/analyzer" ? "active" : ""}
        >
          Analyzer
        </Link>

        <Link
          to="/generator"
          className={location.pathname === "/generator" ? "active" : ""}
        >
          Generator
        </Link>
      </div>
    </nav>
  );
}

