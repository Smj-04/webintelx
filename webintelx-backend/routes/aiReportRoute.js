const express = require("express");
const router = express.Router();

const {
  generateAIReport,
} = require("../controllers/aiReportController");

router.post("/ai-report", generateAIReport);

module.exports = router;
