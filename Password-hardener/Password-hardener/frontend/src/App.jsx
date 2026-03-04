import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Navbar from "./components/NavBar.jsx";
import AnalyzerPage from "./components/AnalyzerPage.jsx";
import GeneratorPage from "./components/GeneratorPage.jsx";

export default function App() {
  return (
    <Router>
      <Navbar />
      <Routes>
        <Route path="/" element={<Navigate to="/analyzer" />} />
        <Route path="/analyzer" element={<AnalyzerPage />} />
        <Route path="/generator" element={<GeneratorPage />} />
      </Routes>
    </Router>
  );
}
