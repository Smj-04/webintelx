const express = require("express");
const router = express.Router();
const { generateQuickScanPDF, generateCustomScanPDF } = require("../controllers/reportController");

router.post("/quickscan/pdf",  generateQuickScanPDF);
router.post("/customscan/pdf", generateCustomScanPDF);

module.exports = router;