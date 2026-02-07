const express = require("express");
console.log("🔥 fullScanRoute.js LOADED");

const router = express.Router();
const { fullScan } = require("../controllers/fullScanController");

router.post("/", fullScan);
module.exports = router;
