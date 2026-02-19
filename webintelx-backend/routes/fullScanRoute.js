const express = require("express");
const router = express.Router();

const {
  fullScan,
  generateFullScanPDF
} = require("../controllers/fullScanController");

router.post("/", fullScan);

// 👇 THIS is what you're missing
router.post("/pdf", async (req, res) => {
  try {
    const { scanData, target } = req.body;
    await generateFullScanPDF(scanData, target, res);
  } catch (err) {
    console.error("PDF route error:", err);
    res.status(500).json({ error: "Failed to generate PDF" });
  }
});

module.exports = router;
