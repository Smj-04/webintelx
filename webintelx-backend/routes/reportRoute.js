const express = require("express");
const router = express.Router();
const { generateQuickScanPDF } = require("../controllers/reportController");

router.post("/quickscan/pdf", generateQuickScanPDF);

module.exports = router;
