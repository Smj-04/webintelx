import React from 'react';
import { Routes, Route } from 'react-router-dom';
import WebIntelX from './WebIntelX';
import CustomScanPage from './pages/CustomScan';
import QuickScanPage from './pages/QuickScan';
import PhishingPage from './pages/PhishingPage';
import FullScanPage from './pages/FullScan';

export default function AppRoutes() {
  return (
    <Routes>
      <Route path="/" element={<WebIntelX />} />
      <Route path="/quick" element={<QuickScanPage />} />
      <Route path="/full" element={<FullScanPage />} />
      <Route path="/custom" element={<FullScanPage />} />
      <Route path="/phishing" element={<PhishingPage />} />
    </Routes>
  );
}
