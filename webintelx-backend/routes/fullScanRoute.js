const express = require("express");
const router = express.Router();
const { fullScan } = require("../controllers/fullScanController");

router.post("/fullscan", fullScan);
module.exports = router;
