const express = require("express");
const router = express.Router();
const { customScan } = require("../controllers/customScanController");

router.post("/customscan", customScan);

module.exports = router;
