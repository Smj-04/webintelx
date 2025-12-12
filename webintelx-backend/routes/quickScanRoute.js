const express = require("express");
const router = express.Router();

const { quickScan } = require("../controllers/quickScanController");

router.post("/", quickScan);

module.exports = router;
