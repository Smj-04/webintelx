import {  Routes, Route } from "react-router-dom";
import WebIntelX from "./WebIntelX";

// Import actual real pages
import QuickScan from "./pages/QuickScan";
import FullScan from "./pages/FullScan";
import CustomScan from "./pages/CustomScan";
import PhishingDetection from "./pages/PhishingPage";


function App() {
  return (
      <Routes>
        console.log("App loaded");

        {/* Home */}
        <Route path="/" element={<WebIntelX />} />

        {/* Scan Pages */}
        <Route path="/quick" element={<QuickScan />} />
        <Route path="/full" element={<FullScan />} />
        <Route path="/custom" element={<CustomScan />} />
        <Route path="/phishing" element={<PhishingDetection />} />
      </Routes>
  );
}

export default App;