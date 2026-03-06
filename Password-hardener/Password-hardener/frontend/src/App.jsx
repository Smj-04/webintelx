import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Navbar from "./components/NavBar.jsx";
import AnalyzerPage from "./components/AnalyzerPage.jsx";
import GeneratorPage from "./components/GeneratorPage.jsx";
import "./styles.css";

export default function App() {
  return (
    <Router>
      <Navbar />
      <Routes>
        {/* Root and /password both land on the analyzer */}
        <Route path="/"          element={<Navigate to="/analyzer" replace />} />
        <Route path="/password"  element={<Navigate to="/analyzer" replace />} />
        <Route path="/analyzer"  element={<AnalyzerPage />} />
        <Route path="/generator" element={<GeneratorPage />} />
      </Routes>
    </Router>
  );
}